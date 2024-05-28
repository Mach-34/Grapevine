use flate2::{Compression, read::GzDecoder};

/**
 * Retrieves a gzipped artifact from a url and unzips it
 * 
 * @param url - the url to retrieve the params from
 * @param chunks - the number of file chunks 
 *   - if < 2 no chunks added
 *   - if >= 2, append -{chunk #} to the url for each chunk
 */
#[wasm_bindgen]
pub async fn retrieve_artifact(url: String, chunks: u8) -> Params {
    // do first iteration (or only if not chunked)
    let mut artifact_url = match chunks {
        0 => url,
        _ => format!("{}-{}", url, 0),
    };
    let mut artifact_binstr = reqwest::get(artifact_url).await.unwrap().text().await.unwrap();
    // if chunked, append to binstr
    if chunks > 1 {
        for i in 1..chunks {
            artifact_url = format!("{}-{}", url, i);
            let chunk = reqwest::get(artifact_url).await.unwrap().text().await.unwrap();
            artifact_binstr.push_str(&chunk);
        }
    }
    // gzip decompress the artifact
    let mut decoder = GzDecoder::new(proof);
    let mut serialized = String::new();
    decoder.read_to_string(&mut serialized).unwrap()
}