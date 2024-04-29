use std::fs;
use set1::*;

fn main() {
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
