#![allow(dead_code)]

/// Set 3
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
use rand::prelude::*;
use std::iter::*;
use std::{fs, thread, time::Duration};

use aescipher::{
    aes_cbc_encryptor_decryptor_factory, aes_ctr_decrypt, decrypt_cbc_block_padding_oracle,
    format_chunks, generate_random_bytevec, strip_pkcs7_padding,
};
use bytearrayconversion::{base64tobytearray, bytearraytohex};
use mersennetwister::{mt19937_32_untemper, MT19937Gen};
use set3::*;
use xorcipher::{decrypt_known_keysize_repeatingkey_xor, decrypt_singlebyte_xor};

fn challenge_17() {
    let base64_strings: Vec<String> = vec![
        "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=".to_string(),
        "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=".to_string(),
        "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==".to_string(),
        "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==".to_string(),
        "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl".to_string(),
        "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==".to_string(),
        "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==".to_string(),
        "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=".to_string(),
        "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=".to_string(),
        "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93".to_string(),
    ];

    let (encryptor, decryptor, iv) = aes_cbc_encryptor_decryptor_factory();

    let encryptor_2 = || -> (Vec<u8>, Vec<u8>) {
        let mut rng = rand::thread_rng();

        // Pick random base64 encoded string
        let idx: usize = rng.gen::<usize>() % base64_strings.len();
        let to_encrypt: Vec<u8> = base64tobytearray(&base64_strings[idx].replace("=", ""));

        (encryptor(&to_encrypt), iv.clone())
    };

    let padding_oracle = |ciphertext: &Vec<u8>| -> bool {
        let decrypted: Vec<u8> = decryptor(ciphertext);
        check_valid_pkcs7_padding(&decrypted)
    };

    let mut ciphertexts = Vec::<Vec<u8>>::new();
    let mut iv = Vec::<u8>::new();

    loop {
        let (ciphertext, got_iv) = encryptor_2();
        if iv.len() == 0 {
            iv = got_iv;
        }
        if !ciphertexts.contains(&ciphertext) {
            ciphertexts.push(ciphertext);
        }

        if ciphertexts.len() == 10 {
            break;
        }
    }
    println!();

    for ciphertext in ciphertexts.iter() {
        let mut ciphertext_chunks: Vec<Vec<u8>> =
            ciphertext.chunks(16).map(|x| x.to_vec()).collect();
        let mut plaintext_chunks = Vec::<Vec<u8>>::new();
        ciphertext_chunks.insert(0, iv.clone());

        for count in 0..ciphertext_chunks.len() - 1 {
            let plaintext_chunk: Vec<u8> = match decrypt_cbc_block_padding_oracle(
                &ciphertext_chunks[count],
                &ciphertext_chunks[count + 1],
                &padding_oracle,
            ) {
                Ok(sth) => sth,
                Err(_) => {
                    println!("Decryption error.");
                    break;
                }
            };

            if count == ciphertext_chunks.len() - 2 {
                match strip_pkcs7_padding(&plaintext_chunk) {
                    Ok(sth) => plaintext_chunks.push(sth),
                    Err(_) => plaintext_chunks.push(plaintext_chunk),
                };
                continue;
            }
            plaintext_chunks.push(plaintext_chunk);
        }
        if plaintext_chunks.len() == ciphertext_chunks.len() - 1 {
            for chunk in plaintext_chunks.into_iter() {
                print!("{}", String::from_utf8(chunk).unwrap());
            }
        }
        println!();
    }
}

fn challenge_18() {
    let ciphertext: Vec<u8> = base64tobytearray(
        &"L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="
            .to_string()
            .replace("=", ""),
    );
    let key: Vec<u8> = b"YELLOW SUBMARINE".to_vec();
    let nonce: Vec<u8> = b"\x00".repeat(key.len() / 2);
    let plaintext: Vec<u8> = aes_ctr_decrypt(&ciphertext, &key, &nonce);
    println!("{}", String::from_utf8(plaintext).unwrap());
}

fn challenge_19() {
    let plaintext_strings: Vec<&str> = vec![
        "SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==",
        "Q29taW5nIHdpdGggdml2aWQgZmFjZXM=",
        "RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==",
        "RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=",
        "SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk",
        "T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
        "T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=",
        "UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
        "QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=",
        "T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl",
        "VG8gcGxlYXNlIGEgY29tcGFuaW9u",
        "QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==",
        "QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=",
        "QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==",
        "QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=",
        "QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
        "VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==",
        "SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==",
        "SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==",
        "VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==",
        "V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==",
        "V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==",
        "U2hlIHJvZGUgdG8gaGFycmllcnM/",
        "VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=",
        "QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=",
        "VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=",
        "V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=",
        "SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==",
        "U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==",
        "U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=",
        "VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==",
        "QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu",
        "SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=",
        "VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs",
        "WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=",
        "SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0",
        "SW4gdGhlIGNhc3VhbCBjb21lZHk7",
        "SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=",
        "VHJhbnNmb3JtZWQgdXR0ZXJseTo=",
        "QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
    ];
    let plaintexts: Vec<Vec<u8>> = plaintext_strings
        .iter()
        .map(|txt_str| base64tobytearray(&txt_str.to_string().replace("=", "")))
        .collect();

    let max_plaintext_len: usize = plaintexts.iter().map(|x| x.len()).max().unwrap();

    let dumb_ctr_encryptor = get_ctr_encryptor();
    let ciphertexts: Vec<Vec<u8>> = plaintexts.iter().map(&dumb_ctr_encryptor).collect();

    let mut ciphertext_chunk_vec = Vec::<Vec<u8>>::new();
    for count in 0..max_plaintext_len {
        let nth_bytes: Vec<u8> = ciphertexts
            .iter()
            .map(|txt| txt.iter().nth(count))
            .filter(|x| x.is_some())
            .map(|x| *x.unwrap())
            .collect();
        ciphertext_chunk_vec.push(nth_bytes);
    }

    // Decrypt keystream from ciphertexts
    let keystream: Vec<u8> = ciphertext_chunk_vec
        .iter()
        .map(|x| {
            let res = decrypt_singlebyte_xor(&bytearraytohex(&x));
            res[0].key
        })
        .collect();

    // Decrypt ciphertexts
    for ciphertext in ciphertexts.iter() {
        let decrypted: Vec<u8> = zip(ciphertext.iter(), keystream.iter())
            .map(|(a, b)| a ^ b)
            .collect();
        match String::from_utf8(decrypted.clone()) {
            Ok(sth) => println!("{}", sth),
            Err(_) => {
                println!(
                    "{}",
                    String::from_utf8(decrypted.into_iter().filter(|x| *x < 127).collect())
                        .unwrap()
                );
            }
        };
    }
}

fn challenge_20() {
    let plaintext_raw = fs::read_to_string("20.txt").unwrap();
    let plaintexts: Vec<Vec<u8>> = plaintext_raw
        .lines()
        .map(|x| base64tobytearray(&x.to_string().replace("=", "")))
        .collect();

    let mut min_plaintext_len: usize = plaintexts.iter().map(|x| x.len()).min().unwrap();
    min_plaintext_len -= min_plaintext_len % 16; // Truncating to the nearest multiple of block
                                                 // size since encryption is in chunks of
                                                 // blocksize bytes.

    let dumb_ctr_encryptor = get_ctr_encryptor();
    let ciphertexts: Vec<Vec<u8>> = plaintexts.iter().map(&dumb_ctr_encryptor).collect();

    // Decrypt keystream from concatenated ciphertexts
    let ciphertexts_concat: Vec<u8> = ciphertexts
        .iter()
        .map(|x| x[..min_plaintext_len].to_vec())
        .flatten()
        .collect();

    let keystream = decrypt_known_keysize_repeatingkey_xor(&ciphertexts_concat, &min_plaintext_len);

    // Decrypt ciphertexts
    for ciphertext in ciphertexts.iter() {
        let decrypted: Vec<u8> = zip(ciphertext.iter(), keystream.iter())
            .map(|(a, b)| a ^ b)
            .collect();
        match String::from_utf8(decrypted.clone()) {
            Ok(sth) => println!("{}", sth),
            Err(_) => {
                println!(
                    "{}",
                    String::from_utf8(decrypted.into_iter().filter(|x| *x < 127).collect())
                        .unwrap()
                );
            }
        };
    }
}

fn challenge_22() {
    let get_rng_output = || -> u32 {
        let mut rng = MT19937Gen::new(13);
        let mut get_random_secs = || -> u64 { 40 + (rng.gen() as u64) % (1000 - 40) };

        let sleep_secs = get_random_secs();
        thread::sleep(Duration::from_secs(sleep_secs));

        let mut rng_2 = MT19937Gen::new(get_unix_timestamp() as u32);
        thread::sleep(Duration::from_secs(get_random_secs()));
        rng_2.gen()
    };

    let randint: u32 = get_rng_output();
    let timestamp: u64 = get_unix_timestamp();

    // Crack the seed of the RNG from the time elapsed since generation
    for secs in 40..1000 {
        let mut rng = MT19937Gen::new((timestamp - secs) as u32);
        if !rng.gen() == randint {
            continue;
        }
        println!("Cracked seed = {}", timestamp - secs);
        break;
    }
}

fn challenge_23() {
    let mut rng = MT19937Gen::new(get_unix_timestamp().try_into().unwrap());
    let mut guessed_state = Vec::<u32>::new();
    let mut randnums = Vec::<u32>::new();
    for count in 0..624 {
        randnums.push(rng.gen());
        guessed_state.push(mt19937_32_untemper(&randnums[count]));
    }
    let mut newrng = MT19937Gen::new_from(&guessed_state);
    assert_eq!(
        (0..624).map(|_| newrng.gen()).collect::<Vec<u32>>(),
        (0..624).map(|_| rng.gen()).collect::<Vec<u32>>()
    );
}

fn challenge_24() {
    let generate_plaintext = || -> Vec<u8> {
        let size = generate_random_bytevec(17)[0];
        let mut plaintext: Vec<u8> = generate_random_bytevec(size as usize);
        plaintext.extend(b"A".to_vec().repeat(14));
        plaintext
    };

    let seed: u16 = 0xABCD;
    let plaintext = generate_plaintext();
    let ciphertext: Vec<u8> = mt19937_keystream_encrypt(&plaintext, &seed);

    println!("Plaintext:");
    format_chunks(&plaintext);

    println!("Encrypted:");
    format_chunks(&ciphertext);

    println!("Decrypted:");
    let decrypted: Vec<u8> = mt19937_keystream_encrypt(&ciphertext, &seed);
    format_chunks(&decrypted);

    let matched_keystream: Vec<u8> = zip(plaintext.iter(), ciphertext.iter())
        .map(|(a, b)| a ^ b)
        .skip(ciphertext.len() - 14)
        .take(14)
        .collect();

    let break_mt19937_16_bit_keystream = || -> u16 {
        for guess in 0..=0xFFFFu16 {
            let mut rng = MT19937Gen::new(guess as u32);
            let keystream: Vec<u8> = (0..ciphertext.len())
                .map(|_| rng.gen())
                .skip(ciphertext.len() - 14)
                .take(14)
                .map(|x| (x & 0xFF) as u8)
                .collect();
            if keystream != matched_keystream {
                continue;
            }
            return guess;
        }
        panic!("Match not found.");
    };

    let guess = break_mt19937_16_bit_keystream();
    assert_eq!(guess, seed);

    let generate_password_reset_token = |txt: &Vec<u8>| -> Vec<u8> {
        mt19937_keystream_encrypt(txt, &((get_unix_timestamp() & 0xFFFF) as u16))
    };

    let password = b"DoNotHackMe".to_vec();
    let token = generate_password_reset_token(&password);
    let timestamp = get_unix_timestamp();
    for secs in 0..=60 {
        let guess = mt19937_keystream_encrypt(&password, &(((timestamp - secs) & 0xFFFF) as u16));
        if guess != token {
            continue;
        }
        println!(
            "Key: {}, secs: {}",
            ((timestamp - secs) & 0xFFFF) as u16,
            secs
        );
        break;
    }
}

fn main() {
    println!();
    println!("Running challenge 17 ...");
    println!();
    challenge_17();

    println!();
    println!("Running challenge 18 ...");
    println!();
    challenge_18();

    println!();
    println!("Running challenge 19 ...");
    println!();
    challenge_19();

    println!();
    println!("Running challenge 20 ...");
    println!();
    challenge_20();

    println!();
    println!("Running challenge 22 ...");
    println!();
    challenge_22();

    println!();
    println!("Running challenge 23 ...");
    println!();
    challenge_23();

    println!();
    println!("Running challenge 24 ...");
    println!();
    challenge_24();
}
