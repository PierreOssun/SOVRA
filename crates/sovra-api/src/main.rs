#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let _guard = sovra_observability::init_tracing(Default::default());
    sovra_api::run::run().await
}
