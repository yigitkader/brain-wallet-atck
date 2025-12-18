// ============================================================================
// notifications.rs - Logging for Found Wallets
// ============================================================================

use anyhow::Result;
use tracing::info;

use crate::pattern::AttackPattern;
use crate::wallet::WalletAddresses;
use crate::balance::BalanceResults;

/// Log wallet findings with detailed information
pub fn log_wallet_found(
    pattern: &AttackPattern,
    wallets: &WalletAddresses,
    balances: &BalanceResults,
) -> Result<()> {
    // Calculate total balance
    let mut total_btc = 0.0;
    for balance in balances.btc.values() {
        total_btc += balance;
    }
    let total_eth = balances.eth.unwrap_or(0.0);
    let total_sol = balances.sol.unwrap_or(0.0);
    let total_value = total_btc + total_eth + total_sol;

    // Use ANSI color codes for highlighting
    // Green for high value, yellow for medium, red for low
    let color_code = if total_value > 1.0 {
        "\x1b[92m" // Bright green for high value
    } else if total_value > 0.1 {
        "\x1b[93m" // Bright yellow for medium value
    } else {
        "\x1b[91m" // Bright red for low value
    };
    let reset_code = "\x1b[0m";

    info!(
        "{}═══════════════════════════════════════════════════════════{}",
        color_code, reset_code
    );
    info!(
        "{}🎉 WALLET FOUND WITH BALANCE! 🎉{}",
        color_code, reset_code
    );
    info!(
        "{}═══════════════════════════════════════════════════════════{}",
        color_code, reset_code
    );
    info!("{}Pattern Type: {}{}", color_code, pattern.pattern_type(), reset_code);
    info!("{}Pattern: {}{}", color_code, pattern, reset_code);
    info!("{}Priority: {}{}", color_code, pattern.priority(), reset_code);
    if let Some(pass) = &wallets.bip39_passphrase {
        info!("{}BIP39 Passphrase: {}{}", color_code, pass, reset_code);
    }
    info!("{}─────────────────────────────────────────────────────────{}", color_code, reset_code);
    
    if !balances.btc.is_empty() {
        info!("{}Bitcoin Wallets:{}", color_code, reset_code);
        for (address, balance) in &balances.btc {
            info!("{}  {}: {:.8} BTC{}", color_code, address, balance, reset_code);
        }
    }
    
    if let Some(eth_balance) = balances.eth {
        info!("{}Ethereum Wallet: {}: {:.8} ETH{}", color_code, wallets.eth, eth_balance, reset_code);
    }
    
    if let Some(sol_balance) = balances.sol {
        if let Some(sol_address) = &wallets.sol {
            info!("{}Solana Wallet: {}: {:.8} SOL{}", color_code, sol_address, sol_balance, reset_code);
        }
    }
    
    info!("{}─────────────────────────────────────────────────────────{}", color_code, reset_code);
    info!("{}Total Value: {:.8} (BTC: {:.8}, ETH: {:.8}, SOL: {:.8}){}", 
        color_code, total_value, total_btc, total_eth, total_sol, reset_code);
    info!(
        "{}═══════════════════════════════════════════════════════════{}",
        color_code, reset_code
    );

    Ok(())
}

