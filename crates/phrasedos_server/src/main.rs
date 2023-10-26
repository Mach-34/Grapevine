use warp::Filter;

#[tokio::main]
async fn main() {
    // Initialize logger
    tracing_subscriber::fmt::init();
    
    // Define warp filter to serve files from static dir
    let static_files = warp::path("static").and(warp::fs::dir("./static"));

    // Start warp server
    warp::serve(static_files).run(([0, 0, 0, 0], 8080)).await;
}
