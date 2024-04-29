use std::fs;
use set1::*;

fn main() {
    // let ciphertext = String::from("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");
    let plaintext = fs::read_to_string("macbeth.txt").unwrap();
    let bin_plaintext = asciitobin(&plaintext);
    let key = 216u8;
    let ciphertext = hex_xor(&bintohex(&bin_plaintext), 
                            &bintohex(&format!("{:08b}", key)
                                .repeat(bin_plaintext.len() / 8)));
    let _matches = decrypt_singlebyte_xor(&ciphertext);
    // for count in 0..5 {
    //     println!("Match {}: {}", count + 1, &matches[count][0..200]);
    // }
}
