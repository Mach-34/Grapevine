mod fs;

pub async fn artifacts_guard() -> Result<(), Box<dyn std::error::Error>> {
    // check if artifacts exist
    if !fs::check_artifacts_exist() {
        println!("Downloading proving artifacts...");
        fs::get_artifacts().await?;
    }
    Ok(())
}