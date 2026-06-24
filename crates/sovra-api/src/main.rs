use crate::run::run;

mod api;
mod config;
mod errors;
mod run;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let _guard = sovra_observability::init_tracing(Default::default());
    run().await
}
