//! Binary entry point: install tracing (guard held for the process lifetime
//! so buffered logs flush on exit), then hand off to
//! [`sovra_cosigner::run::run`]. Everything testable lives in the library.

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let _guard = sovra_observability::init_tracing(Default::default());
    sovra_cosigner::run::run().await
}
