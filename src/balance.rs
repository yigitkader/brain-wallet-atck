use anyhow::{Result, Context, bail};
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
    /// Check if error is a rate limit error (429)
    fn is_rate_limit_error(e: &anyhow::Error) -> bool {
        let error_str = format!("{}", e);
        error_str.contains("429") || error_str.contains("Rate limited") || error_str.contains("rate limit")
    }

    /// Retry balance check with exponential backoff on rate limit errors
    /// Uses jittered exponential backoff to prevent thundering herd problem
    async fn check_with_retry<F, Fut>(&self, check_fn: F, max_retries: u32) -> Result<f64>
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = Result<f64>>,
    {
        let mut last_error = None;
        
        for attempt in 0..max_retries {
            match check_fn().await {
                Ok(balance) => return Ok(balance),
                Err(e) => {
                    last_error = Some(e);
                    // If it's a rate limit error, wait and retry with jittered exponential backoff
                    if Self::is_rate_limit_error(last_error.as_ref().unwrap()) {
                        // Exponential backoff: 2^attempt seconds (max 32 seconds)
                        let base_backoff_secs = 2_u64.pow(attempt.min(5));
                        
                        // Add jitter to prevent thundering herd problem
                        // Multiple threads hitting rate limit at the same time will back off at slightly different times
                        let jitter_ms = Self::calculate_jitter();
                        let backoff_ms = (base_backoff_secs * 1000) + jitter_ms;
                        
                        warn!("Rate limited, waiting {:.2} seconds (with jitter) before retry (attempt {}/{})...", 
                              backoff_ms as f64 / 1000.0, attempt + 1, max_retries);
                        tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                        continue;
                    } else {
                        // Non-rate-limit error, return immediately
                        return Err(last_error.unwrap());
                    }
                }
            }
        }
        
        // All retries exhausted
        Err(last_error.unwrap_or_else(|| anyhow::anyhow!("Max retries exceeded")))
    }
    
    /// Calculate jitter value (0-1000ms) to prevent thundering herd problem
    /// Uses SystemTime for thread-safe pseudo-random jitter without external dependencies
    fn calculate_jitter() -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        // Use current time in nanoseconds to generate pseudo-random jitter
        // This is thread-safe and doesn't require external dependencies
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos() as u64;
        // Jitter between 0-1000ms
        nanos % 1000
    }

    pub async fn check(&self, wallets: &WalletAddresses) -> Result<BalanceResults> {
        let mut results = BalanceResults {
            btc: HashMap::new(),
            eth: None,
            sol: None,
        };

        let max_retries = self.config.rate_limiting.max_retries;

        // Check Bitcoin addresses
        // Note: If any address check fails completely (both APIs exhausted), we return an error
        // This prevents missing wallets with balances due to API failures
        for address in &wallets.btc {
            self.rate_limit().await;

            // Try primary API first with retry logic, fallback to blockchain.com if it fails
            let balance = match self.check_with_retry(
                || self.check_btc_balance(address),
                max_retries
            ).await {
                Ok(b) => b,
                Err(e) => {
                    warn!("Primary BTC API failed for {} after retries: {}, trying fallback...", address, e);
                    // Fallback to blockchain.com API with retry logic
                    match self.check_with_retry(
                        || self.check_btc_balance_blockchain_com(address),
                        max_retries
                    ).await {
                        Ok(b) => b,
                        Err(e2) => {
                            // CRITICAL: Both APIs failed - return error instead of assuming 0 balance
                            // Assuming 0 balance could cause us to miss wallets with actual balances
                            // The caller should handle this error appropriately (retry, skip, or fail)
                            warn!("Both BTC APIs failed for {} after retries: primary={}, fallback={}. Skipping address to avoid missing wallets with balances.", address, e, e2);
                            return Err(anyhow::anyhow!("All BTC API attempts exhausted for {}: primary={}, fallback={}", address, e, e2));
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
            if response.status() == 429 {
                bail!("Rate limited (429) - increase delays in config");
            }
            bail!("API error: {} - {}", response.status(), url);
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
            if response.status() == 429 {
                bail!("Rate limited (429) - increase delays in config");
            }
            bail!("API error: {} - Solana RPC", response.status());
        }

        let data: RpcResponse = response.json().await?;
        let lamports = data.result.map(|r| r.value).unwrap_or(0);

        // Convert lamports to SOL
        Ok(lamports as f64 / 1e9)
    }

    /// Rate limiting implementation
    async fn rate_limit(&self) {
        // Always delay every request to respect API rate limits
        sleep(Duration::from_millis(self.config.rate_limiting.min_delay_ms)).await;

        let count = self.request_count.fetch_add(
            1,
            std::sync::atomic::Ordering::SeqCst
        );

        // Additional cooldown every 50 requests
        if count % 50 == 0 {
            sleep(Duration::from_millis(self.config.rate_limiting.batch_cooldown_ms)).await;
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
            if response.status() == 429 {
                bail!("Rate limited (429) - increase delays in config");
            }
            bail!("API error: {} - {}", response.status(), url);
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