use anyhow::Result;
use clap::Parser;
use std::sync::Arc;
use tracing::{info, warn};

mod config;
mod dictionary;
mod pattern;
mod wallet;
mod balance;
mod stats;
mod checkpoint;
mod bloom;

use crate::config::Config;
use crate::dictionary::DictionaryLoader;
use crate::pattern::PatternGenerator;
use crate::wallet::WalletGenerator;
use crate::balance::BalanceChecker;
use crate::stats::Statistics;
use crate::checkpoint::CheckpointManager;
use crate::bloom::BloomFilterManager;

/// Enterprise-grade brainwallet security auditor
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Config file path
    #[arg(short, long, default_value = "config.toml")]
    config: String,

    /// Resume from checkpoint
    #[arg(short, long)]
    resume: bool,

    /// Clear checkpoint and start fresh
    #[arg(long)]
    clear_checkpoint: bool,

    /// Max patterns to check (overrides config)
    #[arg(short, long)]
    max_patterns: Option<usize>,

    /// Enable verbose logging
    #[arg(short, long)]
    verbose: bool,

    /// Generate default config file and exit
    #[arg(long)]
    generate_config: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Parse CLI arguments
    let args = Args::parse();

    // Handle --generate-config flag
    if args.generate_config {
        let config_content = Config::default_toml();
        std::fs::write("config.toml", config_content)?;
        println!("✅ Default config file created: config.toml");
        return Ok(());
    }

    // Initialize logging
    init_logging(args.verbose)?;

    // Display banner
    display_banner();

    // Ensure output directory exists
    std::fs::create_dir_all("output")?;

    // Load configuration (create default if doesn't exist)
    let config = if !std::path::Path::new(&args.config).exists() {
        warn!("Config file not found: {}. Creating default config...", args.config);
        Config::save_default(&args.config)?;
        Config::load(&args.config)?
    } else {
        Config::load(&args.config)?
    };
    info!("Configuration loaded from: {}", args.config);

    // Override max patterns if specified
    let max_patterns = args.max_patterns.unwrap_or(config.attack.max_patterns);

    // Initialize checkpoint manager
    let checkpoint_manager = CheckpointManager::new("output/checkpoint.json")?;
    
    // Clear checkpoint if requested
    if args.clear_checkpoint {
        checkpoint_manager.clear()?;
        info!("Checkpoint cleared, starting fresh");
    }
    
    let start_index = if args.resume {
        checkpoint_manager.load()?.unwrap_or(0)
    } else {
        0
    };

    info!("Starting from index: {}", start_index);
    
    // Initialize statistics
    let stats = Arc::new(Statistics::new());
    
    // Reset statistics if starting fresh (not resuming)
    if start_index == 0 {
        stats.reset();
    }

    // Initialize bloom filter (prevent duplicate checks)
    let bloom_filter = BloomFilterManager::new(
        config.optimization.bloom_capacity,
        0.001
    );
    
    // Clear bloom filter if starting fresh (not resuming)
    if start_index == 0 {
        bloom_filter.clear();
    }

    // Ensure dictionaries are downloaded
    info!("Ensuring dictionaries are available...");
    DictionaryLoader::ensure_dictionaries(&config).await?;

    // Load dictionaries
    info!("Loading dictionaries...");
    let dictionaries = DictionaryLoader::load_all(&config)?;
    info!("Loaded {} dictionary entries", dictionaries.total_entries());

    // Generate attack patterns
    info!("Generating attack patterns...");
    let mut patterns = PatternGenerator::generate(&dictionaries, &config)?;
    info!("Generated {} attack patterns", patterns.len());

    // Sort by priority (highest first)
    patterns.sort_by_key(|p| std::cmp::Reverse(p.priority()));

    // Initialize components
    let wallet_generator = WalletGenerator::new(&config)?;
    let balance_checker = BalanceChecker::new(&config).await?;

    // Main attack loop
    info!("Starting attack loop...");
    info!("Target: {} patterns", max_patterns.min(patterns.len()));

    let progress_bar = indicatif::ProgressBar::new(max_patterns as u64);
    progress_bar.set_style(
        indicatif::ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})")
            .unwrap()
            .progress_chars("#>-")
    );

    for (i, pattern) in patterns.iter().enumerate().skip(start_index) {
        if i >= max_patterns {
            break;
        }

        // Check bloom filter (skip duplicates)
        if bloom_filter.contains(&pattern) {
            continue;
        }
        bloom_filter.add(&pattern);

        // Generate wallet from pattern
        let wallets = match wallet_generator.generate(&pattern) {
            Ok(w) => w,
            Err(e) => {
                warn!("Failed to generate wallet: {}", e);
                continue;
            }
        };

        // Check balances
        let results = balance_checker.check(&wallets).await?;

        // Update statistics
        stats.increment_checked();

        // Found a wallet with balance!
        if !results.is_empty() {
            stats.increment_found();
            info!("🎉 FOUND WALLET WITH BALANCE!");
            info!("Pattern: {:?}", pattern);
            info!("Results: {:?}", results);

            // Save hit to file
            save_hit(&pattern, &wallets, &results).await?;
        }

        // Update progress
        if i % 100 == 0 {
            progress_bar.set_position(i as u64);
            let rate = stats.get_rate();
            info!("Progress: {} | Rate: {:.2} w/s | Found: {}", 
                i, rate, stats.found());

            // Save checkpoint
            checkpoint_manager.save(i)?;
        }

        // Rate limiting
        if i % 50 == 0 {
            tokio::time::sleep(tokio::time::Duration::from_millis(
                config.rate_limiting.batch_cooldown_ms
            )).await;
        }
    }

    progress_bar.finish_with_message("Attack completed");

    // Final statistics
    info!("═══════════════════════════════════════════════");
    info!("FINAL STATISTICS:");
    info!("Checked: {}", stats.checked());
    info!("Found: {}", stats.found());
    info!("Rate: {:.2} w/s", stats.get_rate());
    info!("Elapsed: {:.2}s", stats.elapsed());
    info!("Bloom filter entries: ~{}", bloom_filter.len());
    info!("═══════════════════════════════════════════════");

    Ok(())
}

fn display_banner() {
    println!("
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║   🎯 BRAINWALLET SECURITY AUDITOR v1.0                   ║
║   Enterprise-Grade Dictionary Attack Framework            ║
║                                                           ║
║   ⚠️  EDUCATIONAL PURPOSE ONLY                            ║
║   Only audit wallets you own or have permission to test  ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
    ");
}

fn init_logging(verbose: bool) -> Result<()> {
    let level = if verbose { "debug" } else { "info" };

    tracing_subscriber::fmt()
        .with_env_filter(level)
        .with_target(false)
        .with_thread_ids(true)
        .with_file(true)
        .with_line_number(true)
        .init();

    Ok(())
}

async fn save_hit(
    pattern: &pattern::AttackPattern,
    wallets: &wallet::WalletAddresses,
    results: &balance::BalanceResults,
) -> Result<()> {
    use std::fs::OpenOptions;
    use std::io::Write;

    let hit = serde_json::json!({
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "pattern": {
            "type": pattern.pattern_type(),
            "value": pattern.to_string(),
            "priority": pattern.priority(),
        },
        "wallets": {
            "btc": wallets.btc,
            "eth": wallets.eth,
            "sol": wallets.sol,
        },
        "balances": results,
    });

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open("output/found_wallets.json")?;

    writeln!(file, "{}", serde_json::to_string_pretty(&hit)?)?;

    Ok(())
}