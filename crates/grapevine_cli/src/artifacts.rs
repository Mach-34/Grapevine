use super::SERVER_URL;

pub async fn get_artifacts() {
    let text = reqwest::get(format!("{}/health", SERVER_URL))
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    println!("Health: {}", text);
}