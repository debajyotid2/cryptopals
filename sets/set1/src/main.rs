#![allow(dead_code)]

use aescipher::{decrypt_aes_ecb, detect_aes_ecb_encryption};
use bytearrayconversion::{base64tobytearray, hextobytearray};
/// Set 1
//
//                    GNU AFFERO GENERAL PUBLIC LICENSE
//                    Version 3, 19 November 2007

// Copyright (C) 2024 Debajyoti Debnath

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.

// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
//
use std::fs;
use xorcipher::{
    decrypt_repeatingkey_xor, decrypt_singlebyte_xor, decrypt_singlebyte_xor_faster,
    encrypt_repeatingkey_xor, encrypt_singlebyte_xor,
};

// Test encryption and decryption of single byte XOR on MacBeth
fn challenge_3() {
    let plaintext = fs::read_to_string("macbeth.txt").unwrap();
    let key = 216u8;
    let ciphertext = encrypt_singlebyte_xor(&plaintext, key);
    let matches = decrypt_singlebyte_xor_faster(&ciphertext);
    for count in 0..5 {
        if matches[count].plaintext == None {
            continue;
        }
        println!("----------------------------------------");
        println!(
            "Match {}: {}",
            count + 1,
            &matches[count].plaintext.as_ref().unwrap()[0..100]
        );
    }
}

// Test challenge 4 text decryption
fn challenge_4() {
    let ciphertext = fs::read_to_string("4.txt").unwrap();
    for (lineno, line) in ciphertext.lines().enumerate() {
        let matches = decrypt_singlebyte_xor(&line.to_string());
        for count in 0..2 {
            if matches[count].plaintext == None {
                continue;
            }
            println!("----------------------------------------------");
            println!(
                "Line {}, Match {}: {}",
                lineno + 1,
                count + 1,
                &matches[count].plaintext.as_ref().unwrap()
            );
        }
    }
}

// Test repeating key XOR decryption
fn challenge_5() {
    let plaintext = String::from("Now that the party is jumping\nWith the bass kicked in, the Vegas are pumpin'\nQuick to the point, to the point, no faking\nI'm cooking MC's like a pound of bacon\nBurning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal\nAnd a hi-hat with a souped up tempo\nI'm on a roll, it's time to go solo\nRollin' in my 5.0\nWith my ragtop down so my hair can blow\nThe girlies on standby");
    let actual_key = String::from("ICE ICE BABY");
    let hex_ciphertext = encrypt_repeatingkey_xor(&plaintext.replace("\n", ""), &actual_key);
    let ascii_ciphertext = String::from_utf8(hextobytearray(&hex_ciphertext))
        .unwrap_or(String::new())
        .replace("\n", "");
    let keys_and_scores = decrypt_repeatingkey_xor(&ascii_ciphertext.as_bytes().to_vec());
    let key: &String = &keys_and_scores[0].0;
    println!("Key = {}", &key);

    println!("------------------------------------------------------");
    println!(
        "Match: {}",
        String::from_utf8(hextobytearray(&encrypt_repeatingkey_xor(
            &ascii_ciphertext,
            key
        )))
        .unwrap()
    );
}

// Decrypt challenge 6 text
fn challenge_6() {
    let ciphertext = fs::read_to_string("6.txt")
        .unwrap_or(String::new())
        .replace("\n", "")
        .replace("=", "");
    let keys_and_scores = decrypt_repeatingkey_xor(&base64tobytearray(&ciphertext));
    let ascii_ciphertext: String =
        String::from_utf8(base64tobytearray(&ciphertext)).unwrap_or(String::new());
    let key: &String = &keys_and_scores[0].0;
    println!("Key = {}", &key);

    println!("------------------------------------------------------");
    println!(
        "Match: {}",
        String::from_utf8(hextobytearray(&encrypt_repeatingkey_xor(
            &ascii_ciphertext,
            key
        )))
        .unwrap()
    );
}

// Decrypt challenge 7 text
fn challenge_7() {
    let base64_ciphertext = fs::read_to_string("7.txt")
        .unwrap_or(String::new())
        .replace("\n", "")
        .replace("=", "");
    let ascii_key = String::from("YELLOW SUBMARINE");
    let decrypted: Vec<u8> = decrypt_aes_ecb(
        &base64tobytearray(&base64_ciphertext),
        &ascii_key.as_bytes().to_vec(),
    );

    println!("Decrypted: \n{}", String::from_utf8(decrypted).unwrap());
}

// Decrypt challenge 8 text
fn challenge_8() {
    let hex_ciphertext = fs::read_to_string("8.txt").unwrap_or(String::new());
    let lineno = detect_aes_ecb_encryption(&hex_ciphertext);

    if lineno == 0 {
        return;
    }
    println!("Found! Line number {} is AES ECB encrypted.", lineno);
}

fn main() {
    println!();
    println!("Running challenge 3 ...");
    println!();
    challenge_3();

    println!();
    println!("Running challenge 4 ...");
    println!();
    challenge_4();

    println!();
    println!("Running challenge 5 ...");
    println!();
    challenge_5();

    println!();
    println!("Running challenge 6 ...");
    println!();
    challenge_6();

    println!();
    println!("Running challenge 7 ...");
    println!();
    challenge_7();

    println!();
    println!("Running challenge 8 ...");
    println!();
    challenge_8();
}
