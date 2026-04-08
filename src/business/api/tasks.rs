//! Background tasks for periodic API operations

use super::client::UserTraffic;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::{interval, MissedTickBehavior};

/// Number of worker threads for the dedicated background task runtime.
/// These tasks are mostly idle (interval-based) with brief gRPC I/O,
/// so 2 threads is sufficient while providing isolation from proxy I/O.
const BG_RUNTIME_WORKERS: usize = 2;

use super::client::ApiManager;
use super::user_manager::UserManager;
use crate::business::stats::ApiStatsCollector;
use crate::logger::log;

/// Format bytes into human-readable string (KB, MB, GB)
fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.2}GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2}MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2}KB", bytes as f64 / KB as f64)
    } else {
        format!("{}B", bytes)
    }
}

/// Background task configuration
#[derive(Debug, Clone)]
pub struct TaskConfig {
    /// Interval for fetching users
    pub fetch_users_interval: Duration,
    /// Interval for reporting traffic
    pub report_traffic_interval: Duration,
    /// Interval for sending heartbeat
    pub heartbeat_interval: Duration,
}

impl Default for TaskConfig {
    fn default() -> Self {
        Self {
            fetch_users_interval: Duration::from_secs(60),
            report_traffic_interval: Duration::from_secs(60),
            heartbeat_interval: Duration::from_secs(60),
        }
    }
}

impl TaskConfig {
    /// Create task config from durations
    pub fn new(fetch_users: Duration, report_traffic: Duration, heartbeat: Duration) -> Self {
        Self {
            fetch_users_interval: fetch_users,
            report_traffic_interval: report_traffic,
            heartbeat_interval: heartbeat,
        }
    }
}

/// Background tasks manager
pub struct BackgroundTasks {
    config: TaskConfig,
    api_manager: Arc<ApiManager>,
    user_manager: Arc<UserManager>,
    stats_collector: Arc<ApiStatsCollector>,
    shutdown_rx: watch::Receiver<bool>,
    shutdown_tx: watch::Sender<bool>,
}

/// Handle for running background tasks with graceful shutdown support
pub struct BackgroundTasksHandle {
    shutdown_tx: watch::Sender<bool>,
    handles: Vec<JoinHandle<()>>,
    /// Dedicated runtime for background tasks - keeps it alive until shutdown.
    /// Under high proxy load (65k+ connections), the main tokio runtime's worker
    /// threads are saturated by proxy I/O, starving background API tasks and
    /// causing gRPC timeouts. This dedicated runtime ensures API tasks always
    /// have available threads.
    _runtime: tokio::runtime::Runtime,
}

impl BackgroundTasksHandle {
    /// Gracefully shutdown all background tasks
    pub async fn shutdown(self) {
        log::info!("Stopping background tasks...");
        let BackgroundTasksHandle {
            shutdown_tx,
            handles,
            _runtime: runtime,
        } = self;
        let _ = shutdown_tx.send(true);

        for (i, handle) in handles.into_iter().enumerate() {
            match tokio::time::timeout(Duration::from_secs(5), handle).await {
                Ok(Ok(())) => log::debug!(task = i, "Background task stopped"),
                Ok(Err(e)) => log::warn!(task = i, error = %e, "Background task panicked"),
                Err(_) => log::warn!(task = i, "Background task shutdown timeout"),
            }
        }

        // Consume the runtime without blocking. Runtime::drop() calls block_on()
        // internally, which panics when called from within an async context.
        runtime.shutdown_background();

        log::info!("Background tasks stopped");
    }
}

impl BackgroundTasks {
    /// Create a new background tasks manager
    pub fn new(
        config: TaskConfig,
        api_manager: Arc<ApiManager>,
        user_manager: Arc<UserManager>,
        stats_collector: Arc<ApiStatsCollector>,
    ) -> Self {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        Self {
            config,
            api_manager,
            user_manager,
            stats_collector,
            shutdown_tx,
            shutdown_rx,
        }
    }

    /// Start all background tasks and return a handle for shutdown
    ///
    /// Creates a dedicated tokio runtime so background API tasks are not
    /// starved by proxy connection I/O on the main runtime.
    pub fn start(self) -> BackgroundTasksHandle {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(BG_RUNTIME_WORKERS)
            .thread_name("api-bg")
            .enable_all()
            .build()
            .expect("Failed to create background task runtime");

        let rt_handle = runtime.handle();
        let handles = vec![
            self.start_fetch_users_task(rt_handle),
            self.start_report_traffic_task(rt_handle),
            self.start_heartbeat_task(rt_handle),
        ];
        log::info!("Background tasks started on dedicated runtime");

        BackgroundTasksHandle {
            shutdown_tx: self.shutdown_tx,
            handles,
            _runtime: runtime,
        }
    }

    /// Start the fetch users task
    fn start_fetch_users_task(&self, rt: &tokio::runtime::Handle) -> JoinHandle<()> {
        let api_manager = Arc::clone(&self.api_manager);
        let user_manager = Arc::clone(&self.user_manager);
        let interval_duration = self.config.fetch_users_interval;
        let mut shutdown_rx = self.shutdown_rx.clone();

        rt.spawn(async move {
            let mut interval = interval(interval_duration);
            interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        if let Err(e) = fetch_users_once(&api_manager, &user_manager).await {
                            log::debug!(error = %e, "Fetch users tick skipped");
                            api_manager.reset_client().await;
                        }
                    }
                    _ = shutdown_rx.changed() => {
                        log::debug!("Fetch users task shutting down");
                        break;
                    }
                }
            }
        })
    }

    /// Start the report traffic task
    fn start_report_traffic_task(&self, rt: &tokio::runtime::Handle) -> JoinHandle<()> {
        let api_manager = Arc::clone(&self.api_manager);
        let stats_collector = Arc::clone(&self.stats_collector);
        let interval_duration = self.config.report_traffic_interval;
        let mut shutdown_rx = self.shutdown_rx.clone();

        rt.spawn(async move {
            let mut interval = interval(interval_duration);
            interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        if let Err(e) = report_traffic_once(&api_manager, &stats_collector).await {
                            log::warn!(error = %e, "Failed to report traffic");
                            api_manager.reset_client().await;
                        }
                    }
                    _ = shutdown_rx.changed() => {
                        log::debug!("Report traffic task shutting down");
                        // Final report before shutdown
                        if let Err(e) = report_traffic_once(&api_manager, &stats_collector).await {
                            log::warn!(error = %e, "Failed to report final traffic");
                        }
                        break;
                    }
                }
            }
        })
    }

    /// Start the heartbeat task
    fn start_heartbeat_task(&self, rt: &tokio::runtime::Handle) -> JoinHandle<()> {
        let api_manager = Arc::clone(&self.api_manager);
        let interval_duration = self.config.heartbeat_interval;
        let mut shutdown_rx = self.shutdown_rx.clone();

        rt.spawn(async move {
            let mut interval = interval(interval_duration);
            // Use Delay instead of Skip to ensure heartbeat is sent as soon as possible
            // after a slow/failed request, rather than skipping the next tick
            interval.set_missed_tick_behavior(MissedTickBehavior::Delay);

            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        match api_manager.heartbeat().await {
                            Ok(()) => log::info!("Heartbeat sent"),
                            Err(e) => {
                                log::warn!(error = %e, "Failed to send heartbeat");
                                api_manager.reset_client().await;
                            }
                        }
                    }
                    _ = shutdown_rx.changed() => {
                        log::debug!("Heartbeat task shutting down");
                        break;
                    }
                }
            }
        })
    }
}

/// Fetch users once and update user manager
async fn fetch_users_once(
    api_manager: &ApiManager,
    user_manager: &UserManager,
) -> anyhow::Result<()> {
    let users = api_manager.fetch_users().await?;
    let total = users.len();
    let (added, removed, uuid_changed, kicked) = user_manager.update(&users);

    log::info!(
        total = total,
        added = added,
        removed = removed,
        uuid_changed = uuid_changed,
        kicked = kicked,
        "Users synchronized"
    );

    Ok(())
}

/// Report traffic once
async fn report_traffic_once(
    api_manager: &ApiManager,
    stats_collector: &ApiStatsCollector,
) -> anyhow::Result<()> {
    let snapshots = stats_collector.reset_all();

    if snapshots.is_empty() {
        return Ok(());
    }

    let traffic_data: Vec<UserTraffic> = snapshots
        .into_iter()
        .filter(|s| s.upload_bytes > 0 || s.download_bytes > 0)
        .map(|s| {
            UserTraffic::with_count(s.user_id, s.upload_bytes, s.download_bytes, s.request_count)
        })
        .collect();

    if traffic_data.is_empty() {
        return Ok(());
    }

    let count = traffic_data.len();
    let total_upload: u64 = traffic_data.iter().map(|t| t.u).sum();
    let total_download: u64 = traffic_data.iter().map(|t| t.d).sum();
    api_manager.submit_traffic(traffic_data).await?;
    log::info!(
        users = count,
        upload = %format_bytes(total_upload),
        download = %format_bytes(total_download),
        "Traffic reported"
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_task_config_default() {
        let config = TaskConfig::default();
        assert_eq!(config.fetch_users_interval, Duration::from_secs(60));
        assert_eq!(config.report_traffic_interval, Duration::from_secs(60));
        assert_eq!(config.heartbeat_interval, Duration::from_secs(60));
    }

    #[test]
    fn test_task_config_new() {
        let config = TaskConfig::new(
            Duration::from_secs(30),
            Duration::from_secs(45),
            Duration::from_secs(120),
        );
        assert_eq!(config.fetch_users_interval, Duration::from_secs(30));
        assert_eq!(config.report_traffic_interval, Duration::from_secs(45));
        assert_eq!(config.heartbeat_interval, Duration::from_secs(120));
    }

    #[test]
    fn test_task_config_clone() {
        let config = TaskConfig::new(
            Duration::from_secs(10),
            Duration::from_secs(20),
            Duration::from_secs(30),
        );
        let cloned = config.clone();
        assert_eq!(cloned.fetch_users_interval, config.fetch_users_interval);
        assert_eq!(
            cloned.report_traffic_interval,
            config.report_traffic_interval
        );
        assert_eq!(cloned.heartbeat_interval, config.heartbeat_interval);
    }

    // Compile-time assertion: BG_RUNTIME_WORKERS must be in [1, 4]
    const _: () = assert!(BG_RUNTIME_WORKERS >= 1);
    const _: () = assert!(BG_RUNTIME_WORKERS <= 4);

    #[test]
    fn test_dedicated_runtime_creates_successfully() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(BG_RUNTIME_WORKERS)
            .thread_name("test-bg")
            .enable_all()
            .build()
            .expect("Failed to create background task runtime");

        // Verify tasks can be spawned and completed on the dedicated runtime
        let result = runtime.block_on(async {
            let handle = tokio::spawn(async { 42 });
            handle.await.unwrap()
        });
        assert_eq!(result, 42);
    }

    #[test]
    fn test_dedicated_runtime_tasks_complete_independently() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let bg_runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(BG_RUNTIME_WORKERS)
            .thread_name("test-bg")
            .enable_all()
            .build()
            .unwrap();

        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = Arc::clone(&counter);

        // Spawn on dedicated runtime and verify it completes
        bg_runtime.block_on(async move {
            let handle = tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(10)).await;
                counter_clone.fetch_add(1, Ordering::Relaxed);
            });
            handle.await.unwrap();
        });

        assert_eq!(counter.load(Ordering::Relaxed), 1);
    }

    /// Regression: BackgroundTasksHandle::shutdown() is async and runs on the
    /// main tokio runtime. When it returns, self._runtime (the dedicated bg
    /// Runtime) is dropped. Runtime::drop() calls block_on() internally, which
    /// panics inside an async context ("Cannot drop a runtime in a context
    /// where blocking is not allowed").
    #[tokio::test]
    async fn test_shutdown_does_not_panic_when_tasks_timeout() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .thread_name("test-bg")
            .enable_all()
            .build()
            .unwrap();

        // Spawn a task that never finishes (simulates stuck gRPC heartbeat)
        let handle = runtime.spawn(async {
            loop {
                tokio::time::sleep(Duration::from_secs(3600)).await;
            }
        });

        let (shutdown_tx, _) = watch::channel(false);

        let bg_handle = BackgroundTasksHandle {
            shutdown_tx,
            handles: vec![handle],
            _runtime: runtime,
        };

        // This should NOT panic — but currently it does because Runtime is
        // dropped inside this async context after shutdown() returns.
        bg_handle.shutdown().await;
    }

    #[test]
    fn test_dedicated_runtime_isolated_from_other_runtime() {
        use std::sync::atomic::{AtomicBool, Ordering};

        // Simulate the real setup: main runtime + dedicated bg runtime
        let main_runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("test-main")
            .enable_all()
            .build()
            .unwrap();

        let bg_runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .thread_name("test-bg")
            .enable_all()
            .build()
            .unwrap();

        let completed = Arc::new(AtomicBool::new(false));
        let completed_clone = Arc::clone(&completed);

        // Spawn task on bg runtime
        let bg_handle = bg_runtime.spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            completed_clone.store(true, Ordering::Relaxed);
        });

        // Flood the main runtime with tasks
        main_runtime.block_on(async {
            let mut flood = vec![];
            for _ in 0..200 {
                flood.push(tokio::spawn(async {
                    tokio::task::yield_now().await;
                }));
            }
            for h in flood {
                let _ = h.await;
            }
        });

        // bg task should complete independently
        bg_runtime.block_on(async { bg_handle.await.unwrap() });
        assert!(completed.load(Ordering::Relaxed));
    }

    /// Regression: unregister must complete before background tasks shutdown.
    ///
    /// Previously the shutdown sequence was:
    ///   1. drain connections (≤5s)
    ///   2. background tasks shutdown (≤15s)  ← could consume entire SIGKILL budget
    ///   3. unregister (never reached)
    ///
    /// Fix: unregister runs before background tasks shutdown, so it completes
    /// within supervisor's stopwaitsecs even when background tasks hang.
    #[tokio::test(start_paused = true)]
    async fn test_unregister_completes_before_bg_shutdown() {
        use std::sync::atomic::{AtomicU8, Ordering};
        use tokio::time::Instant;

        // Track execution order: 0 = not started, 1 = first, 2 = second
        let order = Arc::new(AtomicU8::new(0));
        let unregister_order = Arc::new(AtomicU8::new(0));
        let bg_shutdown_order = Arc::new(AtomicU8::new(0));

        // Simulate the fixed shutdown sequence from main.rs:
        //   1. unregister (fast)
        //   2. background_handle.shutdown() (slow — tasks may hang)
        let seq = Arc::clone(&order);
        let unreg_ord = Arc::clone(&unregister_order);

        // Step 1: unregister (simulated as a fast gRPC call)
        tokio::time::sleep(Duration::from_millis(100)).await; // simulate gRPC roundtrip
        let n = seq.fetch_add(1, Ordering::SeqCst) + 1;
        unreg_ord.store(n, Ordering::SeqCst);

        // Step 2: background tasks shutdown (with a hanging task)
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .thread_name("test-bg")
            .enable_all()
            .build()
            .unwrap();

        let handle = runtime.spawn(async {
            // Simulate a stuck background task (e.g., hung gRPC heartbeat)
            loop {
                tokio::time::sleep(Duration::from_secs(3600)).await;
            }
        });

        let (shutdown_tx, _) = watch::channel(false);
        let bg_handle = BackgroundTasksHandle {
            shutdown_tx,
            handles: vec![handle],
            _runtime: runtime,
        };

        let seq = Arc::clone(&order);
        let bg_ord = Arc::clone(&bg_shutdown_order);

        let before_bg = Instant::now();
        bg_handle.shutdown().await;
        let bg_elapsed = before_bg.elapsed();
        let n = seq.fetch_add(1, Ordering::SeqCst) + 1;
        bg_ord.store(n, Ordering::SeqCst);

        // Verify ordering: unregister (1) before bg shutdown (2)
        assert_eq!(
            unregister_order.load(Ordering::SeqCst),
            1,
            "unregister must execute first"
        );
        assert_eq!(
            bg_shutdown_order.load(Ordering::SeqCst),
            2,
            "bg shutdown must execute second"
        );

        // Verify bg shutdown waited for the 5s timeout (task was stuck)
        assert!(
            bg_elapsed >= Duration::from_secs(5),
            "bg shutdown should have waited for timeout, elapsed: {:?}",
            bg_elapsed
        );
    }
}
