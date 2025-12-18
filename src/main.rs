use anyhow::Result;
use clap::Parser;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{info, warn, error};

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

    /// Number of worker threads (default: 4)
    #[arg(short = 'w', long, default_value = "4")]
    workers: usize,
}

/// Pattern with retry metadata
#[derive(Clone)]
struct PatternJob {
    pattern: pattern::AttackPattern,
    index: usize,
    retry_count: u32,
}

/// Result of pattern processing
enum ProcessResult {
    Success {
        index: usize,
        found: bool,
    },
    RateLimited {
        job: PatternJob,
    },
    Failed {
        index: usize,
        error: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    if args.generate_config {
        let config_content = Config::default_toml();
        std::fs::write("config.toml", config_content)?;
        println!("✅ Default config file created: config.toml");
        return Ok(());
    }

    init_logging(args.verbose)?;
    display_banner();

    std::fs::create_dir_all("output")?;

    let config = if !std::path::Path::new(&args.config).exists() {
        warn!("Config file not found: {}. Creating default config...", args.config);
        Config::save_default(&args.config)?;
        Config::load(&args.config)?
    } else {
        Config::load(&args.config)?
    };
    info!("Configuration loaded from: {}", args.config);

    let max_patterns = args.max_patterns.unwrap_or(config.attack.max_patterns);

    let checkpoint_manager = Arc::new(CheckpointManager::new("output/checkpoint.json")?);

    if args.clear_checkpoint {
        checkpoint_manager.clear()?;
        info!("Checkpoint cleared, starting fresh");
    }

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

    let stats = Arc::new(Statistics::new());

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

    let bloom_filter = Arc::new(BloomFilterManager::new(
        config.optimization.bloom_capacity,
        0.001
    ));

    if start_index == 0 {
        bloom_filter.clear();
    }

    info!("Ensuring dictionaries are available...");
    DictionaryLoader::ensure_dictionaries(&config).await?;

    info!("Loading dictionaries...");
    let dictionaries = DictionaryLoader::load_all(&config)?;
    info!("Loaded {} dictionary entries", dictionaries.total_entries());

    info!("Generating attack patterns (lazy iterator mode)...");
    let patterns_iter = PatternGenerator::generate_iter(&dictionaries, &config);
    info!("Pattern iterator ready");

    // Channel setup
    let (job_tx, job_rx) = mpsc::channel::<PatternJob>(1000);
    // Retry queue is unbounded to avoid deadlock/backpressure during rate-limit storms.
    // Bounded retry can cause `result_aggregator` to block on `.send().await`, stalling progress.
    let (retry_tx, retry_rx) = mpsc::unbounded_channel::<PatternJob>();
    let (result_tx, result_rx) = mpsc::channel::<ProcessResult>(1000);

    let job_rx = Arc::new(tokio::sync::Mutex::new(job_rx));
    let retry_rx = Arc::new(tokio::sync::Mutex::new(retry_rx));

    // Setup CTRL+C handler
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::mpsc::channel::<()>(1);
    let shutdown_tx_clone = shutdown_tx.clone();

    tokio::spawn(async move {
        if let Err(e) = tokio::signal::ctrl_c().await {
            warn!("Failed to listen for Ctrl+C: {}", e);
            return;
        }
        info!("\n🛑 Received Ctrl+C, shutting down gracefully...");
        shutdown_tx_clone.send(()).await.ok();
    });

    // Spawn worker tasks
    info!("Starting {} worker threads...", args.workers);
    let mut worker_handles = vec![];

    for worker_id in 0..args.workers {
        let job_rx = job_rx.clone();
        let retry_rx = retry_rx.clone();
        let result_tx = result_tx.clone();
        let config = config.clone();
        let bloom_filter = bloom_filter.clone();
        let stats = stats.clone();

        let handle = tokio::spawn(async move {
            worker_task(
                worker_id,
                job_rx,
                retry_rx,
                result_tx,
                config,
                bloom_filter,
                stats,
            ).await
        });

        worker_handles.push(handle);
    }

    // Producer loop (run in main task to avoid `'static` requirement of `tokio::spawn`)
    let mut sent_count = 0usize;
    for (relative_idx, pattern) in patterns_iter.skip(start_index).enumerate() {
        // Stop early if we received shutdown (Ctrl+C)
        match shutdown_rx.try_recv() {
            Ok(()) => {
                info!("Producer received shutdown signal, stopping early...");
                break;
            }
            Err(tokio::sync::mpsc::error::TryRecvError::Empty) => {}
            Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                info!("Shutdown channel disconnected, stopping producer...");
                break;
            }
        }

        let i = start_index + relative_idx;
        if i >= max_patterns {
            break;
        }

        // Check bloom filter
        if bloom_filter.contains(&pattern) {
            continue;
        }

        let job = PatternJob {
            pattern,
            index: i,
            retry_count: 0,
        };

        if job_tx.send(job).await.is_err() {
            error!("Job channel closed, stopping producer");
            break;
        }

        sent_count += 1;
    }

    info!("Producer finished: {} patterns sent", sent_count);
    drop(job_tx); // Signal completion

    // Result aggregator task
    let aggregator_handle = tokio::spawn({
        let retry_tx = retry_tx.clone();
        let checkpoint_manager = checkpoint_manager.clone();
        let stats = stats.clone();

        async move {
            result_aggregator(
                result_rx,
                retry_tx,
                checkpoint_manager,
                stats,
                max_patterns,
            ).await
        }
    });

    info!("Cleaning up...");

    // Drop channels to signal workers
    drop(retry_tx);
    drop(result_tx);

    // Wait for all workers
    for handle in worker_handles {
        let _ = handle.await;
    }

    // Wait for aggregator
    let _ = aggregator_handle.await;

    // Final statistics
    if bloom_filter.is_near_capacity() {
        warn!(
            "Bloom filter near capacity: {} / {} (auto-clear threshold ~95%)",
            bloom_filter.len(),
            bloom_filter.capacity()
        );
    }

    let final_stats = serde_json::json!({
        "checked": stats.checked(),
        "found": stats.found(),
        "rate": stats.get_rate(),
        "elapsed_seconds": stats.elapsed(),
        "bloom_filter_entries": bloom_filter.len(),
        "bloom_filter_capacity": bloom_filter.capacity(),
        "bloom_filter_is_empty": bloom_filter.is_empty(),
        "bloom_filter_near_capacity": bloom_filter.is_near_capacity(),
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
    info!(
        "Bloom filter entries: ~{} / {} (near_capacity={}, empty={})",
        bloom_filter.len(),
        bloom_filter.capacity(),
        bloom_filter.is_near_capacity(),
        bloom_filter.is_empty()
    );
    info!("═══════════════════════════════════════════════");

    std::fs::write(
        "output/stats.json",
        serde_json::to_string_pretty(&final_stats)?
    )?;
    info!("Statistics saved to output/stats.json");

    checkpoint_manager.save(
        max_patterns,
        stats.checked(),
        stats.found(),
        Some(stats.start_time())
    )?;

    Ok(())
}

async fn worker_task(
    worker_id: usize,
    job_rx: Arc<tokio::sync::Mutex<mpsc::Receiver<PatternJob>>>,
    retry_rx: Arc<tokio::sync::Mutex<mpsc::UnboundedReceiver<PatternJob>>>,
    result_tx: mpsc::Sender<ProcessResult>,
    config: Config,
    bloom_filter: Arc<BloomFilterManager>,
    stats: Arc<Statistics>,
) {
    let wallet_generator = match WalletGenerator::new(&config) {
        Ok(gen) => gen,
        Err(e) => {
            error!("Worker {}: Failed to create wallet generator: {}", worker_id, e);
            return;
        }
    };

    let balance_checker = match BalanceChecker::new(&config).await {
        Ok(checker) => checker,
        Err(e) => {
            error!("Worker {}: Failed to create balance checker: {}", worker_id, e);
            return;
        }
    };

    loop {
        // Retry jobs should have priority and must not starve behind new work.
        // Use a biased select between the two shared receivers.
        let job = tokio::select! {
            biased;
            retry_job = async {
                let mut retry = retry_rx.lock().await;
                retry.recv().await
            } => retry_job,
            normal_job = async {
                let mut jobs = job_rx.lock().await;
                jobs.recv().await
            } => normal_job,
        };

        let job = match job {
            Some(j) => j,
            None => {
                info!("Worker {}: No more jobs, exiting", worker_id);
                break;
            }
        };

        // Generate wallet
        let wallets = match wallet_generator.generate(&job.pattern) {
            Ok(w) => w,
            Err(e) => {
                warn!("Worker {}: Failed to generate wallet: {}", worker_id, e);
                let _ = result_tx.send(ProcessResult::Failed {
                    index: job.index,
                    error: e.to_string(),
                }).await;
                continue;
            }
        };

        // Check balances
        let results = match balance_checker.check(&wallets).await {
            Ok(r) => r,
            Err(e) => {
                let error_str = e.to_string();

                // Detect rate limit
                if error_str.contains("429") || error_str.contains("Rate limit") {
                    warn!("Worker {}: Rate limited at index {}, requeueing...", worker_id, job.index);

                    if job.retry_count < 5 {
                        let mut retry_job = job.clone();
                        retry_job.retry_count += 1;

                        let _ = result_tx.send(ProcessResult::RateLimited {
                            job: retry_job,
                        }).await;

                        // Backoff
                        tokio::time::sleep(tokio::time::Duration::from_secs(
                            2u64.pow(job.retry_count)
                        )).await;
                    } else {
                        warn!("Worker {}: Max retries exceeded for index {}", worker_id, job.index);
                        let _ = result_tx.send(ProcessResult::Failed {
                            index: job.index,
                            error: format!("Max retries exceeded: {}", error_str),
                        }).await;
                    }
                } else {
                    // Non-rate-limit error
                    warn!("Worker {}: Balance check failed: {}", worker_id, e);
                    let _ = result_tx.send(ProcessResult::Failed {
                        index: job.index,
                        error: error_str,
                    }).await;
                }
                continue;
            }
        };

        // Success - add to bloom filter
        if let Err(e) = bloom_filter.add(&job.pattern) {
            warn!("Worker {}: Bloom filter add failed: {}", worker_id, e);
        }

        stats.increment_checked();

        let found = !results.is_empty();
        if found {
            stats.increment_found();

            if let Err(e) = log_wallet_found(&job.pattern, &wallets, &results) {
                error!("Worker {}: Failed to log wallet: {}", worker_id, e);
            }

            if let Err(e) = save_hit(&job.pattern, &wallets, &results).await {
                error!("Worker {}: Failed to save hit: {}", worker_id, e);
            }
        }

        let _ = result_tx.send(ProcessResult::Success {
            index: job.index,
            found,
        }).await;
    }
}

async fn result_aggregator(
    mut result_rx: mpsc::Receiver<ProcessResult>,
    retry_tx: mpsc::UnboundedSender<PatternJob>,
    checkpoint_manager: Arc<CheckpointManager>,
    stats: Arc<Statistics>,
    max_patterns: usize,
) {
    let mut last_checkpoint = std::time::Instant::now();
    let checkpoint_interval = std::time::Duration::from_secs(300); // 5 min
    let mut last_index = 0;

    while let Some(result) = result_rx.recv().await {
        match result {
            ProcessResult::Success { index, found } => {
                last_index = last_index.max(index);

                if index % 100 == 0 {
                    let progress = if max_patterns > 0 {
                        (index as f64 / max_patterns as f64) * 100.0
                    } else {
                        0.0
                    };
                    info!(
                        "[{}] {:.2}% | Rate: {:.2} w/s | Found: {}",
                        index,
                        progress.min(100.0),
                        stats.get_rate(),
                        stats.found()
                    );
                }

                if found || last_checkpoint.elapsed() > checkpoint_interval {
                    if let Err(e) = checkpoint_manager.save(
                        last_index,
                        stats.checked(),
                        stats.found(),
                        Some(stats.start_time())
                    ) {
                        error!("Failed to save checkpoint: {}", e);
                    }
                    last_checkpoint = std::time::Instant::now();
                }
            }

            ProcessResult::RateLimited { job } => {
                if let Err(e) = retry_tx.send(job) {
                    error!("Failed to send to retry queue: {}", e);
                }
            }

            ProcessResult::Failed { index, error } => {
                warn!("Pattern {} failed: {}", index, error);
                last_index = last_index.max(index);
            }
        }
    }

    info!("Result aggregator finished");

    // Final checkpoint
    if let Err(e) = checkpoint_manager.save(
        last_index,
        stats.checked(),
        stats.found(),
        Some(stats.start_time())
    ) {
        error!("Failed to save final checkpoint: {}", e);
    }
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
        .with_ansi(true)
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
        .open("output/found_wallets.ndjson")?;

    writeln!(file, "{}", serde_json::to_string(&hit)?)?;

    Ok(())
}