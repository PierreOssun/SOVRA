use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

pub struct TracingGuard {
    _inner: WorkerGuard,
}

pub struct TracingConfig {
    // true = JSON (production), false = pretty (dev)
    pub json: bool,
    pub level: String,
}

impl Default for TracingConfig {
    fn default() -> Self {
        Self {
            json: std::env::var("SOVRA_LOG_JSON").is_ok(),
            level: std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()),
        }
    }
}

pub fn init_tracing(config: TracingConfig) -> TracingGuard {
    // Wrap a stdout in a non-blocking writer.
    let (non_blocking, guard) = tracing_appender::non_blocking(std::io::stdout());

    let filter = EnvFilter::try_new(&config.level).unwrap_or_else(|_| EnvFilter::new("info"));

    if config.json {
        // suitable for log aggregators
        tracing_subscriber::registry()
            .with(filter)
            .with(
                tracing_subscriber::fmt::layer()
                    .json()
                    .with_writer(non_blocking),
            )
            .init();
    } else {
        // colored output for local dev
        tracing_subscriber::registry()
            .with(filter)
            .with(
                tracing_subscriber::fmt::layer()
                    .pretty()
                    .with_writer(non_blocking),
            )
            .init();
    }

    TracingGuard { _inner: guard }
}
