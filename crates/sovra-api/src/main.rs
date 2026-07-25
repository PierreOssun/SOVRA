//! Binary entry point: install tracing (guard held for the process lifetime
//! so buffered logs flush on exit), then hand off to [`sovra_api::run::run`].
//! Kept to two lines so everything testable lives in the library crate.

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let _guard = sovra_observability::init_tracing(Default::default());
    sovra_api::run::run().await
}
