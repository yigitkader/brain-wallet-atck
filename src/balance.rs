use anyhow::{Result, Context, bail};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;
use tracing::{debug, warn};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use crate::config::Config;
use crate::wallet::WalletAddresses;

type HttpResult = Result<(u16, String)>;
type HttpFuture = Pin<Box<dyn Future<Output = HttpResult> + Send>>;

/// Process-wide shared rate limiter to avoid multiplying request rate by worker count.
pub struct SharedRateLimiter {
    min_delay_ms: u64,
    batch_cooldown_ms: u64,
    batch_every: u64,
    state: tokio::sync::Mutex<LimiterState>,
}

struct LimiterState {
    last_request_at: std::time::Instant,
    count: u64,
}

impl SharedRateLimiter {
    pub fn new(min_delay_ms: u64, batch_cooldown_ms: u64, batch_every: u64) -> Self {
        Self {
            min_delay_ms,
            batch_cooldown_ms,
            batch_every: batch_every.max(1),
            state: tokio::sync::Mutex::new(LimiterState {
                last_request_at: std::time::Instant::now()
                    .checked_sub(std::time::Duration::from_millis(min_delay_ms))
                    .unwrap_or_else(std::time::Instant::now),
                count: 0,
            }),
        }
    }

    pub async fn acquire(&self) {
        let mut st = self.state.lock().await;

        let min_delay = std::time::Duration::from_millis(self.min_delay_ms);
        let elapsed = st.last_request_at.elapsed();
        if elapsed < min_delay {
            tokio::time::sleep(min_delay - elapsed).await;
        }

        st.count = st.count.saturating_add(1);
        st.last_request_at = std::time::Instant::now();

        if st.count.is_multiple_of(self.batch_every) && self.batch_cooldown_ms > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(self.batch_cooldown_ms)).await;
        }
    }
}

trait HttpClient: Send + Sync {
    fn get(&self, url: String) -> HttpFuture;
    fn post_json(&self, url: String, json_body: String) -> HttpFuture;
}

struct ReqwestHttpClient {
    client: Client,
}

impl HttpClient for ReqwestHttpClient {
    fn get(&self, url: String) -> HttpFuture {
        let client = self.client.clone();
        Box::pin(async move {
            let resp = client.get(&url).send().await
                .with_context(|| format!("Failed to GET {}", url))?;
            let status = resp.status().as_u16();
            let text = resp.text().await.context("Failed to read response body")?;
            Ok((status, text))
        })
    }

    fn post_json(&self, url: String, json_body: String) -> HttpFuture {
        let client = self.client.clone();
        Box::pin(async move {
            let resp = client.post(&url)
                .header("content-type", "application/json")
                .body(json_body)
                .send().await
                .with_context(|| format!("Failed to POST {}", url))?;
            let status = resp.status().as_u16();
            let text = resp.text().await.context("Failed to read response body")?;
            Ok((status, text))
        })
    }
}

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
    http: Arc<dyn HttpClient>,
    btc_limiter: Arc<SharedRateLimiter>,
    eth_limiter: Arc<SharedRateLimiter>,
    sol_limiter: Arc<SharedRateLimiter>,
    request_count: std::sync::Arc<std::sync::atomic::AtomicU64>,
    eth_etherscan_base: String,
    eth_blockcypher_base: String,
    eth_blockchair_base: String,
    sol_rpc_endpoints: Vec<String>,
}

impl BalanceChecker {
    pub async fn new(
        config: &Config,
        btc_limiter: Arc<SharedRateLimiter>,
        eth_limiter: Arc<SharedRateLimiter>,
        sol_limiter: Arc<SharedRateLimiter>,
    ) -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .user_agent("BrainwalletAuditor/1.0")
            .build()?;

        let http: Arc<dyn HttpClient> = Arc::new(ReqwestHttpClient { client });

        Ok(Self {
            config: config.clone(),
            http,
            btc_limiter,
            eth_limiter,
            sol_limiter,
            request_count: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
            eth_etherscan_base: "https://api.etherscan.io".to_string(),
            eth_blockcypher_base: "https://api.blockcypher.com".to_string(),
            eth_blockchair_base: "https://api.blockchair.com".to_string(),
            sol_rpc_endpoints: vec![
                "https://api.mainnet-beta.solana.com".to_string(),
                "https://solana-api.projectserum.com".to_string(),
                "https://rpc.ankr.com/solana".to_string(),
            ],
        })
    }

    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    fn new_for_test(
        config: &Config,
        http: Arc<dyn HttpClient>,
        btc_limiter: Arc<SharedRateLimiter>,
        eth_limiter: Arc<SharedRateLimiter>,
        sol_limiter: Arc<SharedRateLimiter>,
        eth_etherscan_base: String,
        eth_blockcypher_base: String,
        eth_blockchair_base: String,
        sol_rpc_endpoints: Vec<String>,
    ) -> Self {
        Self {
            config: config.clone(),
            http,
            btc_limiter,
            eth_limiter,
            sol_limiter,
            request_count: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
            eth_etherscan_base,
            eth_blockcypher_base,
            eth_blockchair_base,
            sol_rpc_endpoints,
        }
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
        use rand::Rng;
        rand::thread_rng().gen_range(0..1000)
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
        let mut incomplete_errors: Vec<String> = Vec::new();

        // Check Bitcoin addresses
        for address in &wallets.btc {
            self.rate_limit_btc().await;

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
                            warn!("Both BTC APIs failed for {} after retries: primary={}, fallback={}", address, e, e2);
                            return Err(anyhow::anyhow!(
                                "RETRYABLE_BALANCE_CHECK: All BTC API attempts exhausted for {}: primary={}, fallback={}",
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
        self.rate_limit_eth().await;
        match self.check_with_retry(|| self.check_eth_balance(&wallets.eth), max_retries).await {
            Ok(balance) => {
                if balance > 0.0 {
                    results.eth = Some(balance);
                }
            }
            Err(e) => {
                warn!(
                    "Primary ETH API failed for {} after retries: {}, trying fallbacks...",
                    wallets.eth, e
                );
                match self.check_with_retry(|| self.check_eth_balance_blockcypher(&wallets.eth), max_retries).await {
                    Ok(b) => {
                        if b > 0.0 {
                            results.eth = Some(b);
                        }
                    }
                    Err(e2) => {
                        match self.check_with_retry(|| self.check_eth_balance_blockchair(&wallets.eth), max_retries).await {
                            Ok(b) => {
                                if b > 0.0 {
                                    results.eth = Some(b);
                                }
                            }
                            Err(e3) => {
                                warn!(
                                    "All ETH API attempts failed for {}: primary={}, blockcypher={}, blockchair={}. Continuing with other chains.",
                                    wallets.eth, e, e2, e3
                                );
                                incomplete_errors.push(format!(
                                    "ETH failed for {}: primary={}, blockcypher={}, blockchair={}",
                                    wallets.eth, e, e2, e3
                                ));
                            }
                        }
                    }
                }
            }
        }

        // Check Solana address (failures logged but don't fail entire check)
        if let Some(sol_address) = &wallets.sol {
            self.rate_limit_sol().await;
            match self.check_with_retry(|| self.check_sol_balance(sol_address), max_retries).await {
                Ok(balance) => {
                    if balance > 0.0 {
                        results.sol = Some(balance);
                    }
                }
                Err(e) => {
                    warn!(
                        "Primary SOL RPC failed for {} after retries: {}, trying fallbacks...",
                        sol_address, e
                    );
                    // Try remaining endpoints (index 1..)
                    let mut last = e;
                    for endpoint in self.sol_rpc_endpoints.iter().skip(1) {
                        match self.check_with_retry(
                            || self.check_sol_balance_with_endpoint(sol_address, endpoint),
                            max_retries,
                        )
                        .await
                        {
                            Ok(b) => {
                                if b > 0.0 {
                                    results.sol = Some(b);
                                }
                                last = anyhow::anyhow!("resolved via fallback");
                                break;
                            }
                            Err(err) => last = err,
                        }
                    }
                    if last.to_string() != "resolved via fallback" {
                        warn!(
                            "All SOL RPC attempts failed for {}. Last error: {}. Continuing with other chains.",
                            sol_address, last
                        );
                        incomplete_errors.push(format!(
                            "SOL failed for {}: {}",
                            sol_address,
                            last
                        ));
                    }
                }
            }
        }

        // If any enabled chain could not be checked and we found nothing elsewhere, retry the pattern.
        if results.is_empty() && !incomplete_errors.is_empty() {
            return Err(anyhow::anyhow!(
                "RETRYABLE_BALANCE_CHECK: Incomplete chain checks: {}",
                incomplete_errors.join(" | ")
            ));
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

        let (status, body) = self.http.get(url.clone()).await
            .context("Failed to fetch BTC balance")?;

        if !(200..300).contains(&status) {
            if status == 429 {
                bail!("Rate limited (429) - increase delays in config");
            }
            bail!("API error: {} - {}", status, url);
        }

        let data: BlockCypherResponse = serde_json::from_str(&body)?;
        let total_satoshis = data.balance + data.unconfirmed_balance;

        Ok(total_satoshis as f64 / 100_000_000.0)
    }

    /// Check Ethereum balance using Etherscan API
    async fn check_eth_balance(&self, address: &str) -> Result<f64> {
        #[derive(Deserialize)]
        struct EtherscanResponse {
            result: String,
        }

        let address_norm = address.to_lowercase();
        let mut url = format!(
            "{}/api?module=account&action=balance&address={}&tag=latest",
            self.eth_etherscan_base.trim_end_matches('/'),
            address_norm
        );
        if let Some(key) = &self.config.api.etherscan_api_key {
            if !key.is_empty() {
                url.push_str("&apikey=");
                url.push_str(key);
            }
        }

        let (status, body) = self.http.get(url.clone()).await
            .context("Failed to fetch ETH balance")?;

        if !(200..300).contains(&status) {
            if status == 429 {
                bail!("Rate limited (429) - increase delays in config");
            }
            bail!("API error: {} - {}", status, url);
        }

        let data: EtherscanResponse = serde_json::from_str(&body)?;
        let wei: u128 = data.result.parse()
            .context(format!("Failed to parse ETH balance from API response: {}", data.result))?;

        Ok(wei as f64 / 1e18)
    }

    /// Fallback ETH balance check using BlockCypher (no API key required for basic usage)
    async fn check_eth_balance_blockcypher(&self, address: &str) -> Result<f64> {
        #[derive(Deserialize)]
        struct BlockCypherEthResponse {
            balance: u128,
        }

        let address_norm = address.to_lowercase();
        let url = format!(
            "{}/v1/eth/main/addrs/{}/balance",
            self.eth_blockcypher_base.trim_end_matches('/'),
            address_norm
        );
        let (status, body) = self.http.get(url.clone()).await
            .context("Failed to fetch ETH balance (BlockCypher)")?;

        if !(200..300).contains(&status) {
            if status == 429 {
                bail!("Rate limited (429) - increase delays in config");
            }
            bail!("API error: {} - {}", status, url);
        }

        let data: BlockCypherEthResponse = serde_json::from_str(&body)?;
        Ok(data.balance as f64 / 1e18)
    }

    /// Fallback ETH balance check using Blockchair
    async fn check_eth_balance_blockchair(&self, address: &str) -> Result<f64> {
        #[derive(Deserialize)]
        struct BlockchairResp {
            data: HashMap<String, BlockchairAddr>,
        }
        #[derive(Deserialize)]
        struct BlockchairAddr {
            address: BlockchairAddrInner,
        }
        #[derive(Deserialize)]
        struct BlockchairAddrInner {
            balance: String, // can exceed u64, represented as string in wei
        }

        let address_norm = address.to_lowercase();
        let url = format!(
            "{}/ethereum/dashboards/address/{}",
            self.eth_blockchair_base.trim_end_matches('/'),
            address_norm
        );
        let (status, body) = self.http.get(url.clone()).await
            .context("Failed to fetch ETH balance (Blockchair)")?;

        if !(200..300).contains(&status) {
            if status == 429 {
                bail!("Rate limited (429) - increase delays in config");
            }
            bail!("API error: {} - {}", status, url);
        }

        let data: BlockchairResp = serde_json::from_str(&body)?;
        let entry = data
            .data
            .get(address)
            .or_else(|| data.data.get(&address_norm))
            .ok_or_else(|| anyhow::anyhow!("Blockchair returned no data for address {}", address))?;
        let wei: u128 = entry.address.balance.parse()
            .context(format!("Failed to parse ETH balance from Blockchair: {}", entry.address.balance))?;
        Ok(wei as f64 / 1e18)
    }

    /// Check Solana balance using Solana RPC
    async fn check_sol_balance(&self, address: &str) -> Result<f64> {
        let endpoint = self.sol_rpc_endpoints
            .first()
            .ok_or_else(|| anyhow::anyhow!("No Solana RPC endpoints configured"))?;
        self.check_sol_balance_with_endpoint(address, endpoint).await
    }

    async fn check_sol_balance_with_endpoint(&self, address: &str, endpoint: &str) -> Result<f64> {
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

        let body = serde_json::to_string(&request)?;
        let (status, resp_body) = self.http.post_json(endpoint.to_string(), body).await
            .with_context(|| format!("Failed to fetch SOL balance from {}", endpoint))?;

        if !(200..300).contains(&status) {
            if status == 429 {
                bail!("Rate limited (429) - increase delays in config");
            }
            bail!("API error: {} - Solana RPC ({})", status, endpoint);
        }

        let data: RpcResponse = serde_json::from_str(&resp_body)?;
        let lamports = data.result
            .ok_or_else(|| anyhow::anyhow!("Solana RPC returned None result for address {}", address))?
            .value;

        Ok(lamports as f64 / 1e9)
    }

    /// Rate limiting implementation
    async fn rate_limit_btc(&self) {
        self.btc_limiter.acquire().await;

        let count = self
            .request_count
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);

        debug!("API request #{}", count);
    }

    async fn rate_limit_eth(&self) {
        self.eth_limiter.acquire().await;
        let count = self
            .request_count
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        debug!("API request #{}", count);
    }

    async fn rate_limit_sol(&self) {
        self.sol_limiter.acquire().await;
        let count = self
            .request_count
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
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

        let (status, body) = self.http.get(url.clone()).await?;

        if !(200..300).contains(&status) {
            if status == 429 {
                bail!("Rate limited (429) - increase delays in config");
            }
            bail!("API error: {} - {}", status, url);
        }

        let data: BlockchainResponse = serde_json::from_str(&body)?;
        Ok(data.final_balance as f64 / 100_000_000.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mockall::mock;

    #[tokio::test]
    #[ignore]
    async fn test_btc_balance_check() {
        let config = Config::default();
        let limiter = Arc::new(SharedRateLimiter::new(0, 0, 50));
        let checker = BalanceChecker::new(&config, limiter.clone(), limiter.clone(), limiter.clone()).await.unwrap();

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

    mock! {
        Http {}
        impl HttpClient for Http {
            fn get(&self, url: String) -> HttpFuture;
            fn post_json(&self, url: String, json_body: String) -> HttpFuture;
        }
    }

    #[tokio::test]
    async fn test_eth_fallback_primary_fails_blockcypher_succeeds() {
        let mut http = MockHttp::new();
        http.expect_get()
            .returning(|url| {
                Box::pin(async move {
                    if url.contains("etherscan") {
                        Ok((500, r#"{"result":"0"}"#.to_string()))
                    } else if url.contains("blockcypher") {
                        Ok((200, r#"{"balance":1000000000000000000}"#.to_string()))
                    } else if url.contains("blockchair") {
                        Ok((500, r#"{}"#.to_string()))
                    } else {
                        Ok((404, r#"{}"#.to_string()))
                    }
                })
            });
        http.expect_post_json()
            .returning(|_url, _body| Box::pin(async { Ok((500, r#"{}"#.to_string())) }));

        let mut config = Config::default();
        config.rate_limiting.min_delay_ms = 0;
        config.rate_limiting.batch_cooldown_ms = 0;
        config.rate_limiting.max_retries = 1;

        let limiter = Arc::new(SharedRateLimiter::new(0, 0, 50));
        let http: Arc<dyn HttpClient> = Arc::new(http);
        let checker = BalanceChecker::new_for_test(
            &config,
            http,
            limiter.clone(),
            limiter.clone(),
            limiter.clone(),
            "https://api.etherscan.io".to_string(),
            "https://api.blockcypher.com".to_string(),
            "https://api.blockchair.com".to_string(),
            vec!["http://127.0.0.1:1".to_string()], // unused here
        );

        let wallets = WalletAddresses {
            btc: vec![],
            eth: "0x0000000000000000000000000000000000000000".to_string(),
            sol: None,
            bip39_passphrase: None,
        };

        let res = checker.check(&wallets).await.unwrap();
        assert_eq!(res.eth, Some(1.0));
    }

    #[tokio::test]
    async fn test_sol_fallback_primary_fails_secondary_succeeds() {
        let mut http = MockHttp::new();
        http.expect_get()
            .returning(|_url| Box::pin(async { Ok((404, r#"{}"#.to_string())) }));
        http.expect_post_json()
            .returning(|url, _body| {
                Box::pin(async move {
                    if url.contains("primary") {
                        Ok((500, r#"{}"#.to_string()))
                    } else if url.contains("secondary") {
                        Ok((200, r#"{"result":{"value":1000000000}}"#.to_string()))
                    } else {
                        Ok((404, r#"{}"#.to_string()))
                    }
                })
            });

        let mut config = Config::default();
        config.rate_limiting.min_delay_ms = 0;
        config.rate_limiting.batch_cooldown_ms = 0;
        config.rate_limiting.max_retries = 1;

        let limiter = Arc::new(SharedRateLimiter::new(0, 0, 50));
        let http: Arc<dyn HttpClient> = Arc::new(http);
        let checker = BalanceChecker::new_for_test(
            &config,
            http,
            limiter.clone(),
            limiter.clone(),
            limiter.clone(),
            "http://127.0.0.1:1".to_string(),
            "http://127.0.0.1:1".to_string(),
            "http://127.0.0.1:1".to_string(),
            vec!["http://primary".to_string(), "http://secondary".to_string()],
        );

        let wallets = WalletAddresses {
            btc: vec![],
            eth: "0x0000000000000000000000000000000000000000".to_string(),
            sol: Some("So11111111111111111111111111111111111111112".to_string()),
            bip39_passphrase: None,
        };

        let res = checker.check(&wallets).await.unwrap();
        assert_eq!(res.sol, Some(1.0));
    }

    #[tokio::test]
    async fn test_incomplete_chain_checks_are_retryable_when_no_balance_found() {
        let mut http = MockHttp::new();
        http.expect_get()
            .returning(|_url| Box::pin(async { Ok((500, r#"{"result":"0"}"#.to_string())) }));
        http.expect_post_json()
            .returning(|_url, _body| Box::pin(async { Ok((500, r#"{}"#.to_string())) }));

        let mut config = Config::default();
        config.rate_limiting.min_delay_ms = 1;
        config.rate_limiting.batch_cooldown_ms = 0;
        config.rate_limiting.max_retries = 1;

        let limiter = Arc::new(SharedRateLimiter::new(0, 0, 50));
        let http: Arc<dyn HttpClient> = Arc::new(http);
        let checker = BalanceChecker::new_for_test(
            &config,
            http,
            limiter.clone(),
            limiter.clone(),
            limiter.clone(),
            "https://api.etherscan.io".to_string(),
            "https://api.blockcypher.com".to_string(),
            "https://api.blockchair.com".to_string(),
            vec!["https://api.mainnet-beta.solana.com".to_string()],
        );

        let wallets = WalletAddresses {
            btc: vec![],
            eth: "0x0000000000000000000000000000000000000000".to_string(),
            sol: None,
            bip39_passphrase: None,
        };

        let err = checker.check(&wallets).await.unwrap_err().to_string();
        assert!(err.contains("RETRYABLE_BALANCE_CHECK"), "got err: {}", err);
    }
}