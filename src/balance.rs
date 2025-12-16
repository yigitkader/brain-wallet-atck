use anyhow::{Result, Context};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;
use tokio::time::sleep;
use tracing::{debug, warn};

use crate::config::Config;
use crate::wallet::WalletAddresses;

/// Balance results for all chains
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BalanceResults {
    pub btc: HashMap<String, f64>,
    pub eth: Option<f64>,
    pub sol: Option<f64>,
}

impl BalanceResults {
    pub fn is_empty(&self) -> bool {
        self.btc.is_empty() && self.eth.is_none() && self.sol.is_none()
    }
}

/// Balance checker with rate limiting
pub struct BalanceChecker {
    config: Config,
    client: Client,
    request_count: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

impl BalanceChecker {
    pub async fn new(config: &Config) -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .user_agent("BrainwalletAuditor/1.0")
            .build()?;

        Ok(Self {
            config: config.clone(),
            client,
            request_count: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
        })
    }

    /// Check balances for all wallet addresses
    pub async fn check(&self, wallets: &WalletAddresses) -> Result<BalanceResults> {
        let mut results = BalanceResults {
            btc: HashMap::new(),
            eth: None,
            sol: None,
        };

        // Check Bitcoin addresses
        for address in &wallets.btc {
            self.rate_limit().await;

            // Try primary API first, fallback to blockchain.com if it fails
            let balance = match self.check_btc_balance(address).await {
                Ok(b) => b,
                Err(e) => {
                    warn!("Primary BTC API failed for {}: {}, trying fallback...", address, e);
                    // Fallback to blockchain.com API
                    match self.check_btc_balance_blockchain_com(address).await {
                        Ok(b) => b,
                        Err(e2) => {
                            warn!("Fallback BTC API also failed for {}: {}", address, e2);
                            0.0
                        }
                    }
                }
            };

            if balance > 0.0 {
                results.btc.insert(address.clone(), balance);
            }
        }

        // Check Ethereum address
        self.rate_limit().await;
        if let Ok(balance) = self.check_eth_balance(&wallets.eth).await {
            if balance > 0.0 {
                results.eth = Some(balance);
            }
        }

        // Check Solana address
        if let Some(sol_address) = &wallets.sol {
            self.rate_limit().await;
            if let Ok(balance) = self.check_sol_balance(sol_address).await {
                if balance > 0.0 {
                    results.sol = Some(balance);
                }
            }
        }

        Ok(results)
    }

    /// Check Bitcoin balance using BlockCypher API
    async fn check_btc_balance(&self, address: &str) -> Result<f64> {
        #[derive(Deserialize)]
        struct BlockCypherResponse {
            balance: u64,
            unconfirmed_balance: u64,
        }

        let url = format!("https://api.blockcypher.com/v1/btc/main/addrs/{}", address);

        let response = self.client
            .get(&url)
            .send()
            .await
            .context("Failed to fetch BTC balance")?;

        if !response.status().is_success() {
            return Ok(0.0);
        }

        let data: BlockCypherResponse = response.json().await?;
        let total_satoshis = data.balance + data.unconfirmed_balance;

        // Convert satoshis to BTC
        Ok(total_satoshis as f64 / 100_000_000.0)
    }

    /// Check Ethereum balance using Etherscan API
    async fn check_eth_balance(&self, address: &str) -> Result<f64> {
        #[derive(Deserialize)]
        struct EtherscanResponse {
            result: String,
        }

        let url = format!(
            "https://api.etherscan.io/api?module=account&action=balance&address={}&tag=latest",
            address
        );

        let response = self.client
            .get(&url)
            .send()
            .await
            .context("Failed to fetch ETH balance")?;

        if !response.status().is_success() {
            return Ok(0.0);
        }

        let data: EtherscanResponse = response.json().await?;
        let wei: u128 = data.result.parse().unwrap_or(0);

        // Convert wei to ETH
        Ok(wei as f64 / 1e18)
    }

    /// Check Solana balance using Solana RPC
    async fn check_sol_balance(&self, address: &str) -> Result<f64> {
        #[derive(Serialize)]
        struct RpcRequest {
            jsonrpc: String,
            id: u32,
            method: String,
            params: Vec<String>,
        }

        #[derive(Deserialize)]
        struct RpcResponse {
            result: Option<RpcResult>,
        }

        #[derive(Deserialize)]
        struct RpcResult {
            value: u64,
        }

        let request = RpcRequest {
            jsonrpc: "2.0".to_string(),
            id: 1,
            method: "getBalance".to_string(),
            params: vec![address.to_string()],
        };

        let response = self.client
            .post("https://api.mainnet-beta.solana.com")
            .json(&request)
            .send()
            .await
            .context("Failed to fetch SOL balance")?;

        if !response.status().is_success() {
            return Ok(0.0);
        }

        let data: RpcResponse = response.json().await?;
        let lamports = data.result.map(|r| r.value).unwrap_or(0);

        // Convert lamports to SOL
        Ok(lamports as f64 / 1e9)
    }

    /// Rate limiting implementation
    async fn rate_limit(&self) {
        let count = self.request_count.fetch_add(
            1,
            std::sync::atomic::Ordering::SeqCst
        );

        // Basic rate limiting
        if count % 10 == 0 {
            sleep(Duration::from_millis(self.config.rate_limiting.min_delay_ms)).await;
        }

        debug!("API request #{}", count);
    }
}

/// Alternative: Use blockchain.com API for Bitcoin
impl BalanceChecker {
    /// Fallback BTC balance check using blockchain.com
    async fn check_btc_balance_blockchain_com(&self, address: &str) -> Result<f64> {
        #[derive(Deserialize)]
        struct BlockchainResponse {
            #[serde(rename = "final_balance")]
            final_balance: u64,
        }

        let url = format!("https://blockchain.info/rawaddr/{}", address);

        let response = self.client
            .get(&url)
            .send()
            .await?;

        if !response.status().is_success() {
            return Ok(0.0);
        }

        let data: BlockchainResponse = response.json().await?;
        Ok(data.final_balance as f64 / 100_000_000.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_btc_balance_check() {
        let config = Config::default();
        let checker = BalanceChecker::new(&config).await.unwrap();

        // Test with known address with balance (change to valid test address)
        let balance = checker.check_btc_balance("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa").await;
        assert!(balance.is_ok());
    }

    #[tokio::test]
    async fn test_eth_balance_check() {
        let config = Config::default();
        let checker = BalanceChecker::new(&config).await.unwrap();

        // Test with Ethereum Foundation address
        let balance = checker.check_eth_balance("0xde0b295669a9fd93d5f28d9ec85e40f4cb697bae").await;
        assert!(balance.is_ok());
    }
}