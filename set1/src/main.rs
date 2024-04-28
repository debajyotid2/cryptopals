use set1::*;

fn main() {
    let ciphertext = String::from("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");
    let matches = decrypt_singlebyte_xor_faster(&ciphertext);
    for count in 0..5 {
        dbg!("{}", &matches[count]);
    }
}
