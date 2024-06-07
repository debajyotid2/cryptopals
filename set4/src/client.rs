use set4::*;

#[tokio::main]
async fn main() {
    let filename = "foo".to_string();
    let guessed_signature = hmac_sha1_timing_attack(&filename, &"localhost".to_string(), 3000u16).await;
    println!("Guess : {}", &guessed_signature);
    println!("Actual: {}", &hmac_sha1(&filename.as_bytes().to_vec(), &b"key".to_vec()));
}
