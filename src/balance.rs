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

    /// Check if error is a rate limit error (429)
    fn is_rate_limit_error(e: &anyhow::Error) -> bool {
        let error_str = format!("{}", e);
        error_str.contains("429") || error_str.contains("Rate limited") || error_str.contains("rate limit")
    }

    /// Retry balance check with exponential backoff on rate limit errors
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
                    if Self::is_rate_limit_error(last_error.as_ref().unwrap()) {
                        let base_backoff_secs = 2_u64.pow(attempt.min(5));
                        let jitter_ms = Self::calculate_jitter();
                        let backoff_ms = (base_backoff_secs * 1000) + jitter_ms;

                        warn!("Rate limited, waiting {:.2} seconds (with jitter) before retry (attempt {}/{})...",
                              backoff_ms as f64 / 1000.0, attempt + 1, max_retries);
                        tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                        continue;
                    } else {
                        return Err(last_error.unwrap());
                    }
                }
            }
        }

        Err(last_error.unwrap_or_else(|| anyhow::anyhow!("Max retries exceeded")))
    }

    fn calculate_jitter() -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        use std::time::{SystemTime, UNIX_EPOCH};
        use std::thread;

        let thread_id = thread::current().id();
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();

        let mut hasher = DefaultHasher::new();
        thread_id.hash(&mut hasher);
        nanos.hash(&mut hasher);
        let hash = hasher.finish();

        hash % 1000
    }

    /// Check balances for all wallet addresses
    /// Returns partial results on API failures (doesn't fail entire check)
    pub async fn check(&self, wallets: &WalletAddresses) -> Result<BalanceResults> {
        let mut results = BalanceResults {
            btc: HashMap::new(),
            eth: None,
            sol: None,
        };

        let max_retries = self.config.rate_limiting.max_retries;

        // Check Bitcoin addresses
        for address in &wallets.btc {
            self.rate_limit().await;

            let balance = match self.check_with_retry(
                || self.check_btc_balance(address),
                max_retries
            ).await {
                Ok(b) => b,
                Err(e) => {
                    warn!("Primary BTC API failed for {} after retries: {}, trying fallback...", address, e);
                    match self.check_with_retry(
                        || self.check_btc_balance_blockchain_com(address),
                        max_retries
                    ).await {
                        Ok(b) => b,
                        Err(e2) => {
                            // FIXED: Return error to trigger retry in worker
                            // This allows the pattern to be re-queued instead of lost
                            warn!("Both BTC APIs failed for {} after retries: primary={}, fallback={}", address, e, e2);
                            return Err(anyhow::anyhow!(
                                "All BTC API attempts exhausted for {}: primary={}, fallback={}",
                                address, e, e2
                            ));
                        }
                    }
                }
            };

            if balance > 0.0 {
                results.btc.insert(address.clone(), balance);
            }
        }

        // Check Ethereum address (failures logged but don't fail entire check)
        self.rate_limit().await;
        match self.check_eth_balance(&wallets.eth).await {
            Ok(balance) => {
                if balance > 0.0 {
                    results.eth = Some(balance);
                }
            }
            Err(e) => {
                warn!("ETH balance check failed for {}: {}. Continuing with other chains.", wallets.eth, e);
            }
        }

        // Check Solana address (failures logged but don't fail entire check)
        if let Some(sol_address) = &wallets.sol {
            self.rate_limit().await;
            match self.check_sol_balance(sol_address).await {
                Ok(balance) => {
                    if balance > 0.0 {
                        results.sol = Some(balance);
                    }
                }
                Err(e) => {
                    warn!("SOL balance check failed for {}: {}. Continuing with other chains.", sol_address, e);
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
            if response.status() == 429 {
                bail!("Rate limited (429) - increase delays in config");
            }
            bail!("API error: {} - {}", response.status(), url);
        }

        let data: EtherscanResponse = response.json().await?;
        let wei: u128 = data.result.parse()
            .context(format!("Failed to parse ETH balance from API response: {}", data.result))?;

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
        let lamports = data.result
            .ok_or_else(|| anyhow::anyhow!("Solana RPC returned None result for address {}", address))?
            .value;

        Ok(lamports as f64 / 1e9)
    }

    /// Rate limiting implementation
    async fn rate_limit(&self) {
        sleep(Duration::from_millis(self.config.rate_limiting.min_delay_ms)).await;

        let count = self.request_count.fetch_add(
            1,
            std::sync::atomic::Ordering::SeqCst
        );

        if count % 50 == 0 {
            sleep(Duration::from_millis(self.config.rate_limiting.batch_cooldown_ms)).await;
        }

        debug!("API request #{}", count);
    }
}

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
    #[ignore]
    async fn test_btc_balance_check() {
        let config = Config::default();
        let checker = BalanceChecker::new(&config).await.unwrap();

        let balance = checker.check_btc_balance("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa").await;
        assert!(balance.is_ok());
        assert!(balance.unwrap() > 0.0);
    }

    #[test]
    fn test_balance_results_is_empty() {
        let mut results = BalanceResults {
            btc: HashMap::new(),
            eth: None,
            sol: None,
        };
        assert!(results.is_empty());

        results.btc.insert("test".to_string(), 0.0);
        assert!(!results.is_empty());
    }

    #[test]
    fn test_rate_limit_error_detection() {
        let error1 = anyhow::anyhow!("Rate limited (429)");
        assert!(BalanceChecker::is_rate_limit_error(&error1));

        let error2 = anyhow::anyhow!("HTTP 429 Too Many Requests");
        assert!(BalanceChecker::is_rate_limit_error(&error2));

        let error3 = anyhow::anyhow!("Connection timeout");
        assert!(!BalanceChecker::is_rate_limit_error(&error3));
    }
}