// ============================================================================
// notifications.rs - Webhook and Email Notifications
// ============================================================================

use anyhow::Result;
use reqwest::Client;
use serde::Serialize;
use tracing::{info, warn};

use crate::config::NotificationConfig;
use crate::pattern::AttackPattern;
use crate::wallet::WalletAddresses;
use crate::balance::BalanceResults;

/// Notification manager for webhooks and emails
pub struct NotificationManager {
    config: NotificationConfig,
    client: Client,
}

impl NotificationManager {
    pub fn new(config: NotificationConfig) -> Self {
        Self {
            config,
            client: Client::new(),
        }
    }

    /// Send notification when wallet is found
    pub async fn notify_wallet_found(
        &self,
        pattern: &AttackPattern,
        wallets: &WalletAddresses,
        balances: &BalanceResults,
    ) -> Result<()> {
        if !self.config.alert_on_find {
            return Ok(());
        }

        let message = format!(
            "🎉 Wallet Found!\n\nPattern: {}\nType: {}\nPriority: {}\n\nWallets:\nBTC: {:?}\nETH: {}\nSOL: {:?}\n\nBalances:\n{:?}",
            pattern,
            pattern.pattern_type(),
            pattern.priority(),
            wallets.btc,
            wallets.eth,
            wallets.sol,
            balances
        );

        // Send webhook if configured
        if let Some(ref webhook_url) = self.config.webhook_url {
            if !webhook_url.is_empty() {
                self.send_webhook(webhook_url, &message).await?;
            }
        }

        // Send email if configured
        if let Some(ref email) = self.config.email {
            if !email.is_empty() {
                self.send_email(email, &message).await?;
            }
        }

        Ok(())
    }

    /// Send webhook notification
    async fn send_webhook(&self, url: &str, message: &str) -> Result<()> {
        #[derive(Serialize)]
        struct WebhookPayload {
            content: String,
        }

        let payload = WebhookPayload {
            content: message.to_string(),
        };

        match self.client
            .post(url)
            .json(&payload)
            .send()
            .await
        {
            Ok(response) => {
                if response.status().is_success() {
                    info!("Webhook notification sent successfully");
                } else {
                    warn!("Webhook notification failed: {}", response.status());
                }
            }
            Err(e) => {
                warn!("Failed to send webhook: {}", e);
            }
        }

        Ok(())
    }

    /// Send email notification (simplified - uses webhook or logs)
    async fn send_email(&self, _email: &str, message: &str) -> Result<()> {
        // For now, we'll log the email notification
        // In production, you'd use an email service like SendGrid, SES, etc.
        info!("Email notification (to {}): {}", _email, message);
        
        // TODO: Implement actual email sending using a service like:
        // - SendGrid
        // - AWS SES
        // - SMTP server
        
        Ok(())
    }
}

