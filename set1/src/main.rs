use std::fs;
use set1::*;

fn main() {
    
    // Test encryption and decryption of single byte XOR on MacBeth
    // let plaintext = fs::read_to_string("macbeth.txt").unwrap();
    // let key = 216u8;
    // let ciphertext = encrypt_singlebyte_xor(&plaintext, key);
    // let matches = decrypt_singlebyte_xor_faster(&ciphertext);
    // for count in 0..5 {
    //     println!("----------------------------------------");
    //     println!("Match {}: {}", count + 1, &matches[count]);
    //     println!("----------------------------------------");
    // }
    
    // Decrypt challenge 4 text
    let ciphertext = fs::read_to_string("4.txt").unwrap();
    for line in ciphertext.lines() {
        let matches = decrypt_singlebyte_xor(&line.to_string());
        println!("----------------------------------------------");
        for count in 0..2 {
            println!("Match {}: {}", count + 1, &matches[count]);
        }
        println!("----------------------------------------------");
    }
    
}
