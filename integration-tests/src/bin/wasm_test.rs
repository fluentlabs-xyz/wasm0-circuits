use std::time::{Instant};
use integration_tests::integration_test_circuits::SUPER_CIRCUIT_TEST;
use integration_tests::log_init;

#[tokio::main]
async fn main() {
    log_init();

    let start = Instant::now();
    SUPER_CIRCUIT_TEST.lock().await.test_at_block_num(2, false).await;
    let elapsed = start.elapsed();

    println!("elapsed time: {}", elapsed.as_secs());
}