#[tokio::main]
async fn main() -> anyhow::Result<()> {
    secret_broker::run().await
}
