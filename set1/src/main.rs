// use std::fs;
use set1::*;

fn main() {
    // Test encryption and decryption of single byte XOR on MacBeth
    // let plaintext = fs::read_to_string("macbeth.txt").unwrap();
    // let key = 216u8;
    // let ciphertext = encrypt_singlebyte_xor(&plaintext, key);
    // let matches = decrypt_singlebyte_xor_faster(&ciphertext);
    // for count in 0..5 {
    //     if matches[count].plaintext == None {
    //         continue;
    //     }
    //     println!("----------------------------------------");
    //     println!("Match {}: {}", count + 1, 
    //         &matches[count].plaintext.as_ref().unwrap()[0..100]);
    // }
    
    // Decrypt challenge 4 text
    // let ciphertext = fs::read_to_string("4.txt").unwrap();
    // for (lineno, line) in ciphertext.lines().enumerate() {
    //     let matches = decrypt_singlebyte_xor(&line.to_string());
    //     for count in 0..2 {
    //         if matches[count].plaintext == None {
    //             continue;
    //         }
    //         println!("----------------------------------------------");
    //         println!("Line {}, Match {}: {}", 
    //             lineno + 1, count + 1, &matches[count].plaintext
    //                                                 .as_ref().unwrap());
    //     }
    // }
    
    // Decrypt challenge 6 text
    let ciphertext = String::from("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f");
    let matches = decrypt_repeatingkey_xor(&hextobytearray(&ciphertext));
    println!("{}", String::from_utf8(matches).unwrap());
}
