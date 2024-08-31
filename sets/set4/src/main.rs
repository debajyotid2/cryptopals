#![allow(dead_code)]
/// Set 4
// 
//                     GNU AFFERO GENERAL PUBLIC LICENSE
//                        Version 3, 19 November 2007
// 
//     Copyright (C) 2024 Debajyoti Debnath
// 
//     This program is free software: you can redistribute it and/or modify
//     it under the terms of the GNU Affero General Public License as published
//     by the Free Software Foundation, either version 3 of the License, or
//     (at your option) any later version.
// 
//     This program is distributed in the hope that it will be useful,
//     but WITHOUT ANY WARRANTY; without even the implied warranty of
//     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//     GNU Affero General Public License for more details.
// 
//     You should have received a copy of the GNU Affero General Public License
//     along with this program.  If not, see <https://www.gnu.org/licenses/>.
// 



use std::{fs, iter::zip, net::SocketAddr};
use axum::{
    body::Body,
    routing::get, 
    Router, extract::Query, 
    http::StatusCode, 
    response::{IntoResponse, Response}
};
use set3::get_ctr_encryptor;
use set4::*;
use bytearrayconversion::{base64tobytearray, hextobytearray};
use aescipher::{aes_cbc_decrypt, aes_cbc_encrypt, aes_ctr_decrypt, generate_random_bytevec};
use vecofbits::BitVec;
use md4hash::compute_md_padding_md4;
use sha1hash::compute_md_padding_sha1;

fn challenge_25() {
    let plaintext: Vec<u8> = base64tobytearray(&fs::read_to_string("25.txt")
                                                        .expect("File 25.txt not found.")
                                                        .replace("\n", ""));
    let key = generate_random_bytevec(16);
    let ciphertext = aes_ctr_decrypt(&plaintext, &key, &b"\x00".repeat(8).to_vec());

    let editing_api_call = |ciphertext_arg: &Vec<u8>, offset: usize, newtext: &Vec<u8>| -> Vec<u8> {
        edit_ctr_ciphertext(ciphertext_arg, &key, offset, newtext).unwrap_or(Vec::<u8>::new())
    };

    // Recover original plaintext
    let recovered_keystream = editing_api_call(&ciphertext, 0, &b"\x00".repeat(ciphertext.len()).to_vec());
    let recovered_plaintext: Vec<u8> = zip(ciphertext.iter(), recovered_keystream.iter())
                                .map(|(a, b)| a ^ b)
                                .collect();
    assert_eq!(recovered_plaintext, plaintext);
}

fn challenge_26() {
    let enc = get_ctr_encryptor();
    let prefix: Vec<u8> = b"comment1=cooking%20MCs;userdata=".to_vec();
    let suffix: Vec<u8> = b";comment2=%20like%20a%20pound%20of%20bacon".to_vec();
    
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

        enc(&plaintext)
    };

    let find_admin_info = |text: &String| -> bool {
        text.contains(";admin=true;")
    };
    
    // Generate ciphertext
    let plaintext: Vec<u8> = b"AAAAAAAAAAAAAAAA".to_vec();
    let ciphertext: Vec<u8> = encryptor(&plaintext);
    
    // Inject malicious bytes into ciphertext
    let target_keystream: Vec<u8> = zip(plaintext.iter(), ciphertext.chunks(16).nth(2).unwrap().iter())
                                            .map(|(a, b)| a ^ b)
                                            .collect();
    let mal_bytes: Vec<u8> = zip(target_keystream.iter(), b"AAAA;admin=true;".iter())
                                    .map(|(a, b)| a ^ b)
                                    .collect();
    let mut mal_ciphertext = ciphertext.clone();
    mal_ciphertext[32..48].copy_from_slice(&mal_bytes[..]);
    
    // Test for admin info
    let decrypted_str: String = String::from_utf8(enc(&mal_ciphertext)).unwrap();
    
    println!("Does string contain an admin profile? : {}", find_admin_info(&decrypted_str));
}

fn challenge_27() {
    let random_key: Vec<u8> = generate_random_bytevec(16);

    let encryptor = |plaintext: &Vec<u8>| -> Vec<u8> {
        if let Err(_) = check_ascii_chars(plaintext) {
            panic!("Invalid ASCII characters in plaintext.");
        };
        
       aes_cbc_encrypt(plaintext, &random_key, &random_key)
    };

    let decryptor = |ciphertext_arg: &Vec<u8>| -> Vec<u8> {
        let decrypted = aes_cbc_decrypt(ciphertext_arg, &random_key, &random_key);
        match check_ascii_chars(&decrypted) {
            Ok(sth) => sth,
            Err(set4::Error::InvalidASCIIChars(val)) => {
                eprintln!("Invalid ASCII characters found.");
                val
            },
            _ => panic!("Decryption error.")
        }
    };

    let xor_bytearrays = |arr1: &Vec<u8>, arr2: &Vec<u8>| -> Vec<u8> {
        zip(arr1.iter(), arr2.iter()).map(|(a, b)| *a ^ *b).collect()
    };
    
    // Generate ciphertext
    let plaintext: Vec<u8> = b"fooingaroundwithDDDDDDDDDDDDDDDDbarbazbaebagbatb".to_vec();
    let ciphertext: Vec<u8> = encryptor(&plaintext);
    
    // Inject malicious bytes into ciphertext
    let mut mal_ciphertext: Vec<u8> = ciphertext.clone();
    mal_ciphertext[(16 * 0)..(16 * 1)].copy_from_slice(ciphertext.chunks(16).nth(0).unwrap());
    mal_ciphertext[(16 * 1)..(16 * 2)].copy_from_slice(&b"\x00".repeat(16).to_vec()[..]);
    mal_ciphertext[(16 * 2)..(16 * 3)].copy_from_slice(ciphertext.chunks(16).nth(0).unwrap());

    // Decrypt malicious bytes
    let decrypted: Vec<u8> = decryptor(&mal_ciphertext);

    // Recover key by XOR-ing first and third chunk. This works because
    // the IV is the same as the key, but it won't if the attacker does
    // not have control over the first chunk.
    let recovered_key: Vec<u8> = xor_bytearrays(&decrypted.chunks(16).nth(0).unwrap().to_vec(), &decrypted.chunks(16).nth(2).unwrap().to_vec());
    assert_eq!(recovered_key, random_key);
}

fn challenge_28() {
    let generate_mac = get_secret_prefix_sha1_mac_generator();
    let mac = generate_mac(&b"The quick brown fox jumps over the lazy dog".to_vec());
    println!("{}", mac);
}

fn challenge_29() {
    let my_message = BitVec::new_from_bytearray(&b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon".to_vec());
    let my_custom_message = BitVec::new_from_bytearray(&b";admin=true".to_vec());

    let generate_mac = get_secret_prefix_sha1_mac_generator();
    
    let key_len: usize = 16 * 8;
    let initial_mac = generate_mac(&my_message.to_bytearray());
    let new_mac = sha1_length_extension_attack(&my_message, &initial_mac, &my_custom_message, key_len);
    println!("Initial MAC: {}\nNew MAC: {}", &initial_mac, &new_mac);

    let mut message_to_forge: BitVec = my_message.clone();
    let padding: BitVec = compute_md_padding_sha1(my_message.len() + key_len);
    message_to_forge.extend(padding.get_data().clone());
    message_to_forge.extend(my_custom_message.get_data().clone());
    
    assert_eq!(generate_mac(&message_to_forge.to_bytearray()), new_mac);
}

fn challenge_30() {
    let my_message = BitVec::new_from_bytearray(&b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon".to_vec());
    let my_custom_message = BitVec::new_from_bytearray(&b";admin=true".to_vec());
    let generate_mac = get_secret_prefix_md4_mac_generator();
    
    let key_len: usize = 16 * 8;
    let initial_mac = generate_mac(&my_message.to_bytearray());
    let new_mac = md4_length_extension_attack(&my_message, &initial_mac, &my_custom_message, key_len);
    println!("Initial MAC: {}\nNew MAC: {}", &initial_mac, &new_mac);

    let mut message_to_forge: BitVec = my_message.clone();
    let padding: BitVec = compute_md_padding_md4(my_message.len() + key_len);
    message_to_forge.extend(padding.get_data().clone());
    message_to_forge.extend(my_custom_message.get_data().clone());
    
    assert_eq!(generate_mac(&message_to_forge.to_bytearray()), new_mac);
}

#[tokio::main(flavor = "current_thread")]
async fn challenge_31() {
    async fn validate_signature(Query(fileinfo): Query<FileInfo>) -> impl IntoResponse {
        let key = b"key".to_vec();
        let actual: String = hmac_sha1(&fileinfo.file.as_bytes().to_vec(), &key);
        if insecure_compare(&hextobytearray(&fileinfo.signature), &hextobytearray(&actual)) {
            Response::builder()
                .status(StatusCode::OK)
                .body(Body::from("Signature is valid."))
                .unwrap()
        } else {
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::from("Signature is invalid."))
                .unwrap()
        } 
    }

    async fn handle_default() -> impl IntoResponse {
        Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Body::from("Page not found"))
                .unwrap()
    }

    let app = Router::new()
                .route("/:test", get(validate_signature))
                .route("/", get(handle_default));
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));

    println!("Listening on {} ...", &addr);
    axum_server::bind(addr)
            .serve(app.into_make_service())
            .await
            .unwrap();
}

fn main() {
    println!();
    println!("Running challenge 25 ...");
    println!();
    challenge_25();

    println!();
    println!("Running challenge 26 ...");
    println!();
    challenge_26();

    println!();
    println!("Running challenge 27 ...");
    println!();
    challenge_27();

    println!();
    println!("Running challenge 28 ...");
    println!();
    challenge_28();

    println!();
    println!("Running challenge 29 ...");
    println!();
    challenge_29();

    println!();
    println!("Running challenge 30 ...");
    println!();
    challenge_30();
    
    // Uncomment these lines to run the server for challenge 31
    // println!();
    // println!("Running challenge 31 ...");
    // println!();
    // challenge_31();
}
