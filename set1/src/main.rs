use set1::*;

fn main() {
    let ciphertext = String::from("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");
    decrypt_singlebyte_xor(&ciphertext);
}
