use std::fs;
use set1::*;

// Test encryption and decryption of single byte XOR on MacBeth
#[allow(dead_code)]
fn test_singlebyte_xor_encryption() {
    let plaintext = fs::read_to_string("macbeth.txt").unwrap();
    let key = 216u8;
    let ciphertext = encrypt_singlebyte_xor(&plaintext, key);
    let matches = decrypt_singlebyte_xor_faster(&ciphertext);
    for count in 0..5 {
        if matches[count].plaintext == None {
            continue;
        }
        println!("----------------------------------------");
        println!("Match {}: {}", count + 1, 
            &matches[count].plaintext.as_ref().unwrap()[0..100]);
    }
}

// Test challenge 4 text decryption
#[allow(dead_code)]
fn test_challenge_4_text_decryption() {
    let ciphertext = fs::read_to_string("4.txt").unwrap();
    for (lineno, line) in ciphertext.lines().enumerate() {
        let matches = decrypt_singlebyte_xor(&line.to_string());
        for count in 0..2 {
            if matches[count].plaintext == None {
                continue;
            }
            println!("----------------------------------------------");
            println!("Line {}, Match {}: {}", 
                lineno + 1, count + 1, &matches[count].plaintext
                                                    .as_ref().unwrap());
        }
    }
}

// Test repeating key XOR decryption
#[allow(dead_code)]
fn test_repeating_key_xor_decryption() {
    let hex_ciphertext = String::from("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f");
    let ascii_ciphertext = String::from_utf8(hextobytearray(&hex_ciphertext)).unwrap_or(String::new()).replace("\n", "");
    let keys_and_scores = decrypt_repeatingkey_xor(&ascii_ciphertext.as_bytes().to_vec());
    let key: &String = &keys_and_scores[0].0;
    println!("Key = {}", &key);

    println!("------------------------------------------------------");
    println!("Match: {}", String::from_utf8(hextobytearray(
                &encrypt_repeatingkey_xor(&ascii_ciphertext, key))).unwrap());
}

// Decrypt challenge 6 text
#[allow(dead_code)]
fn test_challenge_6_text_decryption() {
    let ciphertext = fs::read_to_string("6.txt")
                            .unwrap_or(String::new())
                            .replace("\n", "")
                            .replace("=", "");
    let keys_and_scores = decrypt_repeatingkey_xor(&base64tobytearray(&ciphertext));
    let ascii_ciphertext: String = String::from_utf8(base64tobytearray(&ciphertext)).unwrap_or(String::new());                       
    let key: &String = &keys_and_scores[0].0;
    println!("Key = {}", &key);

    println!("------------------------------------------------------");
    println!("Match: {}", String::from_utf8(hextobytearray(
                &encrypt_repeatingkey_xor(&ascii_ciphertext, key))).unwrap());
}

fn main() {
    test_repeating_key_xor_decryption();
}
