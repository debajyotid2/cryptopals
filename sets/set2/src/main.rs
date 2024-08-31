#![allow(dead_code)]
/// Set 2
// 
//                     GNU AFFERO GENERAL PUBLIC LICENSE
//                     Version 3, 19 November 2007

//  Copyright (C) 2024 Debajyoti Debnath

//  This program is free software: you can redistribute it and/or modify
//  it under the terms of the GNU Affero General Public License as published
//  by the Free Software Foundation, either version 3 of the License, or
//  (at your option) any later version.

//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU Affero General Public License for more details.

//  You should have received a copy of the GNU Affero General Public License
//  along with this program.  If not, see <https://www.gnu.org/licenses/>.
// 

use std::fs;
use set2::*;
use xorcipher::hex_xor;
use bytearrayconversion::{hextobytearray, bytearraytohex, base64tobytearray};
use aescipher::{
    format_chunks,
    aes_ecb_encrypt,
    aes_cbc_encrypt,
    aes_cbc_decrypt,
    strip_pkcs7_padding,
    generate_random_bytevec,
    guess_aes_ecb_appended_bytes,
    detect_aes_ecb_encryption,
    get_aes_ecb_blocksize_and_appended_bytes_size,
    aes_ecb_encryptor_decryptor_factory
};

// Test challenge 10 encryption
fn challenge_9() {
    let base64_ciphertext: String = fs::read_to_string("10.txt")
                            .unwrap_or(String::new())
                            .replace("\n", "")
                            .replace("=", "");
    let init_vec: Vec<u8> = b"\x00".to_vec().repeat(16);
    let key: Vec<u8> = b"YELLOW SUBMARINE".to_vec();
    let encrypted: Vec<u8> = aes_cbc_decrypt(&base64tobytearray(&base64_ciphertext), &init_vec, &key);
    println!("Decrypted = \n{}", &String::from_utf8(encrypted).unwrap());
}

// Test encryption oracle
fn challenge_11() {
    let plaintext = b"\x00".to_vec().repeat(3 * 16 - 5);
    let mut count: usize = 0;
    while count < 50 {
        println!("--------------------------------------------");
        println!("Iteration {}: ", count + 1);
        let ciphertext: Vec<u8> = random_aes_encryptor(&plaintext, true);
        encryption_oracle(&ciphertext);
        count += 1;
    }
}

// Test challenge 12 decryption
fn challenge_12() {
    let random_key: Vec<u8> = generate_random_bytevec(16usize);
    let encryptor = |plaintext_arg: &Vec<u8>| -> Vec<u8> {
        let mut plaintext: Vec<u8> = plaintext_arg.clone();
        let bytes_to_append: Vec<u8> = base64tobytearray(&String::from("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"));

        plaintext.extend(&bytes_to_append);
        aes_ecb_encrypt(&plaintext, &random_key)
    };
    
    // Detect AES ECB encryption block size  
    let (blocksize, _, suffix_bytes_size): (usize, usize, usize) = get_aes_ecb_blocksize_and_appended_bytes_size(&encryptor);

    println!("AES encryptor has block size of {} bits.", blocksize * 8);
    println!("AES encryptor appends {} bytes to the plaintext as a suffix before encryption.", suffix_bytes_size);
    
    // Detect whether AES ECB is being used
    if detect_aes_ecb_encryption(&bytearraytohex(&encryptor(&b"\xce".to_vec().repeat(2 * blocksize)))) != 0 {
        println!("The encryption algorithm is AES ECB.");
    }

    // Brute force guess the appended bytes one byte at a time
    let guessed_bytes: Vec<u8> = guess_aes_ecb_appended_bytes(blocksize, 0usize, suffix_bytes_size, &encryptor);

    // assert!(guessed_bytes.len() >= suffix_bytes_size);
    println!("Guessed suffix:\n{}", String::from_utf8(guessed_bytes).unwrap());
}

// Test challenge 13
fn challenge_13() {
    let (encryptor, decryptor) = aes_ecb_encryptor_decryptor_factory();
    let (blocksize, _, suffix_bytes_size) = get_aes_ecb_blocksize_and_appended_bytes_size(&encryptor);

    println!("Block size: {} bytes, appended bytes size: {} bytes.", &blocksize, &suffix_bytes_size);
    
    let plaintext: Vec<u8> = profile_for(&"tesmanlicambalampur@gmail.com".to_string()).as_bytes().to_vec();
    let ciphertext: Vec<u8> = encryptor(&plaintext);
    let decrypted: Vec<u8> = decryptor(&ciphertext);
    
    assert_eq!(&plaintext, &strip_pkcs7_padding(&decrypted).unwrap());
    
    println!("Plaintext:");
    for chunk in decrypted.clone().chunks(blocksize) {
        println!("{}", String::from_utf8(chunk.to_vec()).unwrap());
    }

    let malicious_plaintext: Vec<u8> = profile_for(&"tesmanlicambalampur@gmail.admin\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00com".to_string()).as_bytes().to_vec();
    let mal_ciphertext_chunks: Vec<Vec<u8>> = (encryptor(&malicious_plaintext)).chunks(blocksize).map(|a| a.to_vec()).collect();
    let mut temp: Vec<&Vec<u8>> = mal_ciphertext_chunks.iter().skip(3).take(mal_ciphertext_chunks.len() - 4).collect();
    
    temp.insert(0, &mal_ciphertext_chunks[0]);
    temp.insert(1, &mal_ciphertext_chunks[1]);
    temp.push(&mal_ciphertext_chunks[2]);

    let mal_ciphertext: Vec<u8> = temp.iter().map(|&x| x).flatten().map(|&x| x).collect();
    let mal_decrypted: Vec<u8> = decryptor(&mal_ciphertext);

    println!("Malicious profile decrypted:");
    for chunk in mal_decrypted.clone().chunks(blocksize) {
        println!("{}", String::from_utf8(chunk.to_vec()).unwrap());
    }
}

// Test challenge 14
fn challenge_14(prefix_size: usize) {
    let random_prefix_bytes: Vec<u8> = generate_random_bytevec(prefix_size);
    let random_key: Vec<u8> = generate_random_bytevec(16usize);

    let encryptor = |plaintext_arg: &Vec<u8>| -> Vec<u8> {
        let mut plaintext: Vec<u8> = random_prefix_bytes.clone();
        let bytes_to_append: Vec<u8> = base64tobytearray(&String::from("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"));
        
        plaintext.extend(&plaintext_arg.clone());
        plaintext.extend(&bytes_to_append);

        aes_ecb_encrypt(&plaintext, &random_key)
    };
    
    // Detect AES ECB encryption block size  
    let (blocksize, num_prefix_bytes, num_suffix_bytes): (usize, usize, usize) = get_aes_ecb_blocksize_and_appended_bytes_size(&encryptor);

    println!("AES encryptor has block size of {} bits.", blocksize * 8);
    println!("AES encryptor appends {} bytes to the plaintext as a prefix and {} bytes as a suffix before encryption.", &num_prefix_bytes, &num_suffix_bytes);
    
    assert_eq!(blocksize, 16usize);
    assert_eq!(num_prefix_bytes, prefix_size);
    assert_eq!(num_suffix_bytes, 136usize);

    // Detect whether AES ECB is being used
    if detect_aes_ecb_encryption(&bytearraytohex(&encryptor(&b"\xce".to_vec().repeat(2 * blocksize)))) != 0 {
        println!("The encryption algorithm is AES ECB.");
    }

    // Brute force guess the appended bytes one byte at a time
    let guessed_bytes: Vec<u8> = guess_aes_ecb_appended_bytes(blocksize, num_prefix_bytes, num_suffix_bytes, &encryptor);

    println!("Guessed suffix:\n{}", String::from_utf8(guessed_bytes).unwrap());
}

// Test challenge 16 CBC bitflip attack
fn challenge_16() {
    let prefix: Vec<u8> = b"comment1=cooking%20MCs;userdata=".to_vec();
    let suffix: Vec<u8> = b";comment2=%20like%20a%20pound%20of%20bacon".to_vec();
    let random_key: Vec<u8> = generate_random_bytevec(16usize);
    let random_iv: Vec<u8> = generate_random_bytevec(16usize);
    
    let encryptor = |plaintext_arg: &Vec<u8>| -> Vec<u8> {
        let mut plaintext: Vec<u8> = prefix.clone();
        plaintext.extend(&plaintext_arg.clone());
        plaintext.extend(&suffix);
        
        // Escape any ; and = characters in the plaintext
        let mut offset: usize = 0;
        for (count, byteval) in plaintext_arg.iter().enumerate() {
            if *byteval == b';' || *byteval == b'=' {
                plaintext.insert(prefix.len() + count + offset, b'"');
                plaintext.insert(prefix.len() + count + 2 + offset, b'"');
                offset += 2;
            }
        }

        aes_cbc_encrypt(&plaintext, &random_iv, &random_key)
    };

    let decryptor = |ciphertext_arg: &Vec<u8>| -> Vec<u8> {
        aes_cbc_decrypt(ciphertext_arg, &random_iv, &random_key)
    };

    let find_admin_info = |text: &String| -> bool {
        text.contains(";admin=true;")
    };

    let xor_bytearrays = |arr1: &Vec<u8>, arr2: &Vec<u8>| -> Vec<u8> {
        hextobytearray(&hex_xor(&bytearraytohex(&arr1), &bytearraytohex(&arr2)))
    };

    let plaintext: Vec<u8> = b"< put anything >DDDDDDDDDDDDDDDD".to_vec();
    let ciphertext: Vec<u8> = encryptor(&plaintext);
    
    // Inject malicious bytes into ciphertext
    let mut ciphertext_chunks: Vec<Vec<u8>> = ciphertext.chunks(16usize).map(|x| x.to_vec()).collect();

    // We exploit the fact that D ^ \x44 = \0
    let bytes_to_insert: Vec<u8> = xor_bytearrays(&b"\x44".repeat(16).to_vec(), &b"fooba;admin=true".to_vec());
    ciphertext_chunks[2] = xor_bytearrays(&bytes_to_insert, &ciphertext_chunks[2]);

    // Decrypt
    let decrypted_malbytes: Vec<u8> = decryptor(&ciphertext_chunks.into_iter().flatten().collect::<Vec<u8>>());
    
    let decrypted_bytes: Vec<u8> = decryptor(&ciphertext);
    
    // Check the decrypted byte chunks (for debugging)
    println!();
    println!("Actual decrypted bytes:");
    format_chunks(&decrypted_bytes);

    println!();
    println!("Fake decrypted bytes:");
    format_chunks(&decrypted_malbytes);
        
    let mut clean_string = String::new();
    for (count, chunk) in decrypted_malbytes.chunks(16).enumerate() {
        if count == 2 { continue; }
        match String::from_utf8(chunk.to_vec()) {
            Ok(sth) => clean_string.push_str(&sth),
            Err(_) => clean_string.push_str(&String::from_utf8(strip_pkcs7_padding(&chunk.to_vec()).unwrap()).unwrap()),
        }
    }

    println!();
    println!("Decrypted mal-bytes: {}", &clean_string);
    println!("Does plaintext contain admin information? : {}", find_admin_info(&clean_string));
}

fn main() {
    println!();
    println!("Running challenge 9 ...");
    println!();
    challenge_9();

    println!();
    println!("Running challenge 11 ...");
    println!();
    challenge_11();

    println!();
    println!("Running challenge 12 ...");
    println!();
    challenge_12();

    println!();
    println!("Running challenge 13 ...");
    println!();
    challenge_13();

    println!();
    println!("Running challenge 14 ...");
    println!();
    challenge_14(0);

    println!();
    println!("Running challenge 15 ...");
    println!();
    challenge_14(7);

    println!();
    println!("Running challenge 16 ...");
    println!();
    challenge_16();
}
