// use std::fs;
use set1::*;

fn main() {
    
    // Test encryption and decryption of single byte XOR on MacBeth
    // let plaintext = fs::read_to_string("macbeth.txt").unwrap();
    // let key = 216u8;
    // let ciphertext = encrypt_singlebyte_xor(&plaintext, key);
    // let matches = decrypt_singlebyte_xor_faster(&ciphertext);
    // for count in 0..5 {
    //     println!("----------------------------------------");
    //     println!("Match {}: {}", count + 1, &matches[count].plaintext);
    //     println!("----------------------------------------");
    // }
    
    // Decrypt challenge 4 text
    // let ciphertext = fs::read_to_string("4.txt").unwrap();
    // for line in ciphertext.lines() {
    //     let matches = decrypt_singlebyte_xor(&line.to_string());
    //     println!("----------------------------------------------");
    //     for count in 0..2 {
    //         println!("Match {}: {}", count + 1, &matches[count].plaintext);
    //     }
    //     println!("----------------------------------------------");
    // }
    
    // Decrypt challenge 6 text
    let ciphertext = String::from("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f");
    let _matches = decrypt_repeatingkey_xor(&hextobin(&ciphertext));
}
