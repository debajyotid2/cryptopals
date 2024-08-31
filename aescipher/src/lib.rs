/// aescipher library
//
//                    GNU AFFERO GENERAL PUBLIC LICENSE
//                    Version 3, 19 November 2007
//
// Copyright (C) 2024 Debajyoti Debnath
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
//


use std::iter::zip;
use itertools::{Itertools, EitherOrBoth::*};
use aes::Aes128;
use aes::cipher::{
    BlockEncrypt, BlockDecrypt, KeyInit,
    generic_array::GenericArray,
};
use xorcipher::hex_xor;
use bytearrayconversion::{hextobytearray, bytearraytohex};

mod helpers;

pub use helpers::*;

#[derive(Debug, PartialEq)]
pub enum Error {
    NoMatchFound,
    DecryptionError
}

pub fn decrypt_aes_ecb(ciphertext: &Vec<u8>, key: &Vec<u8>) -> Vec<u8> {
    let key_arr: [u8; 16] = key.clone().try_into().unwrap();
    let key_val = GenericArray::from(key_arr);

    let cipher = Aes128::new(&key_val);

    let ciphertext_blocks: Vec<[u8; 16]> = ciphertext
                    .chunks(16)
                    .map(|chunk| {
                        let arr: [u8; 16] = chunk
                                .try_into()
                                .unwrap_or({
                            let mut chunk_copy = chunk.to_vec();
                            chunk_copy    
                                .extend_from_slice(
                                    &vec![0u8].repeat(16 - chunk.len()));
                            let val: [u8; 16] = chunk_copy
                                            .try_into().unwrap();
                            val
                        });
                        arr
                    })
                    .collect();
    ciphertext_blocks
            .iter()
            .map(|block| {
                let mut decrypted = GenericArray::from(*block);
                cipher.decrypt_block(&mut decrypted);
                decrypted.to_vec()
            })
            .flatten()
            .collect()
}

pub fn detect_aes_ecb_encryption(hex_ciphertext: &String) -> usize {
    let ciphertext: Vec<Vec<[u8; 16]>> = hex_ciphertext
                    .lines()
                    .map(|line| hextobytearray(&line.to_string()))
                    .map(|vec| {
                         vec.chunks(16)
                            .map(|chunk| {
                                let arr: [u8; 16] = chunk.try_into().unwrap();
                                arr
                            })
                            .collect()
                        })
                    .collect();
    for (lineno, vec) in ciphertext.iter().enumerate() {
        for arr in vec {
            let count = vec.iter().filter(|el| **el == *arr).count();
            if count < 2 {
                continue;
            } else {
                return lineno + 1;
            }
        }
    }
    0
}

pub fn aes_ecb_encrypt(plaintext: &Vec<u8>, key: &Vec<u8>) -> Vec<u8> {
    let key_arr: [u8; 16] = key.clone().try_into().unwrap();
    let key_val = GenericArray::from(key_arr);

    let cipher = Aes128::new(&key_val);

    let plaintext_blocks: Vec<[u8; 16]> = plaintext
                    .chunks(16)
                    .map(|chunk| {
                        let arr: [u8; 16] = match chunk.try_into() {
                            Ok(sth) => sth,
                            Err(_) => {
                                let val: [u8; 16] = pad_pkcs7(
                                    &chunk.to_vec(), 16)
                                        .unwrap()
                                        .try_into()
                                        .unwrap();
                                val
                            }
                        };
                        arr
                    })
                    .collect();
    plaintext_blocks
            .iter()
            .map(|block| {
                let mut encrypted = GenericArray::from(*block);
                cipher.encrypt_block(&mut encrypted);
                encrypted.to_vec()
            })
            .flatten()
            .collect()
}

pub fn aes_cbc_decrypt(ciphertext: &Vec<u8>, iv: &Vec<u8>, key: &Vec<u8>) -> Vec<u8> {
    let mut old_ciphertext = iv.to_vec();
    let mut plaintext = String::new();

    for chunk in ciphertext.chunks(16) {
        let decrypted: String = bytearraytohex(&decrypt_aes_ecb(&chunk.to_vec(), key));
        plaintext.push_str(&hex_xor(&decrypted, &bytearraytohex(&old_ciphertext)));
        old_ciphertext = chunk.to_vec();
    }
    hextobytearray(&plaintext)
}

pub fn aes_cbc_encrypt(plaintext: &Vec<u8>, iv: &Vec<u8>, key: &Vec<u8>) -> Vec<u8> {
    let mut ciphertext = Vec::<Vec<u8>>::new();
    let mut plaintext_padded = plaintext.clone();
    if plaintext.len() % 16usize != 0 {
        let padded_plaintext_size: usize = plaintext.len() + 16usize - plaintext.len() % 16usize;
        plaintext_padded = (pad_pkcs7(plaintext, padded_plaintext_size)).unwrap();
    }

    ciphertext.push(iv.clone());

    for chunk in plaintext_padded.chunks(16) {
        let temp: Vec<u8> = hextobytearray(&hex_xor(&bytearraytohex(&chunk.to_vec()), &bytearraytohex(&ciphertext[ciphertext.len()-1])));
        let encrypted: Vec<u8> = aes_ecb_encrypt(&temp, key);
        ciphertext.push(encrypted);
    }
    ciphertext.remove(0);
    ciphertext.into_iter().flatten().collect()
}

pub fn get_aes_ecb_blocksize_and_appended_bytes_size(ecb_encryptor: &dyn Fn(&Vec<u8>) -> Vec<u8>) -> (usize, usize, usize) {
    let mut num_prefix_bytes: isize = 0;
    let mut num_appended_bytes_total: usize = 0;
    let mut num_bytes_ciphertext: usize = 0;
    let mut blocksize: usize = 0;
    let mut prefix_bytes_calculated: bool = false;

    let mut prev_encrypted = Vec::<u8>::new();

    for count in 0..=64usize {
        let plaintext: Vec<u8> = b"\x01".to_vec().repeat(count);
        let encrypted: Vec<u8> = ecb_encryptor(&plaintext);
        
        // Guess number of prefixed bytes
        if prev_encrypted.len() != 0 && !prefix_bytes_calculated {
            let mut num_more_common_bytes: isize = 0;
            let mut iterator = encrypted.iter().skip(num_prefix_bytes as usize)
                                            .zip_longest(prev_encrypted.iter().skip(num_prefix_bytes as usize));
            while let Some(Both(l, r)) = iterator.next() {
                if l != r {
                    break;
                }
                num_more_common_bytes += 1;
            }
            if num_more_common_bytes >= 16 {
                if count != 1 {
                    num_prefix_bytes -= count as isize - 1;
                    prefix_bytes_calculated = true;
                }
                num_prefix_bytes += num_more_common_bytes / 8 * 8;
            }
        }
        prev_encrypted = encrypted.clone();
        
        // Guess block size and total number of appended bytes (prefix + suffix)
        if encrypted.len() > num_bytes_ciphertext && num_bytes_ciphertext != 0 && blocksize == 0 {
            blocksize = encrypted.len() - num_bytes_ciphertext;
            num_appended_bytes_total = num_bytes_ciphertext - count - 1;
        };
        if prefix_bytes_calculated && blocksize != 0 {
            break;
        }
        num_bytes_ciphertext = encrypted.len();
    }
    (blocksize, num_prefix_bytes as usize, num_appended_bytes_total - num_prefix_bytes as usize)
}

pub fn guess_next_byte_brute_force(ecb_encryptor: &dyn Fn(&Vec<u8>) -> Vec<u8>, 
                prev_bytes: &Vec<u8>, ciphertext_bytes: &Vec<u8>, chunk_idx: usize, num_blocks_to_skip: usize) -> Option<u8> {
    for byteval in 0..=255u8 {
        let mut plaintext: Vec<u8> = prev_bytes.clone();
        plaintext.push(byteval);
        let encrypted_block: Vec<u8> = ecb_encryptor(&plaintext)
                                            .chunks(ciphertext_bytes.len())
                                            .skip(num_blocks_to_skip)
                                            .nth(chunk_idx)
                                            .unwrap()
                                            .to_vec();
        if encrypted_block == *ciphertext_bytes {
            return Some(byteval);
        }
    }
    return None;
}

pub fn guess_aes_ecb_appended_bytes(blocksize: usize, num_prefix_bytes: usize, num_suffix_bytes: usize, encryptor: &dyn Fn(&Vec<u8>) -> Vec<u8>) -> Vec<u8> {
    let offset: usize = if num_prefix_bytes % blocksize != 0 {
        blocksize - (num_prefix_bytes % blocksize)
    } else { 0 };
    let num_blocks_to_skip: usize = (num_prefix_bytes as f32 / blocksize as f32).ceil() as usize;

    let encrypted_vec_chunks: Vec<(Vec<u8>, Vec<Vec<u8>>)> = ((1+offset)..(blocksize+1+offset)).rev()
                                            .map(|size| {
                                                let plaintext: Vec<u8> = b"A".to_vec().repeat(size);
                                                let encrypted: Vec<u8> = encryptor(&plaintext);
                                                let encrypted_chunks: Vec<Vec<u8>> = encrypted
                                                                    .chunks(blocksize)
                                                                    .skip(num_blocks_to_skip)
                                                                    .map(|x| x.to_vec())
                                                                    .collect::<Vec<Vec<u8>>>();
                                                (plaintext, encrypted_chunks)
                                            })
                                            .collect();
    
    let mut guessed_bytes = Vec::<u8>::new();
    
    for chunk_idx in 0..=(num_suffix_bytes / blocksize) {
        for count in 0..blocksize {
            if chunk_idx == 0 && count == 0 {
                continue;
            }
            let mut prev_bytes: Vec<u8> = encrypted_vec_chunks[count].0.clone();
            let ciphertext_chunk: &Vec<u8> = match encrypted_vec_chunks[count].1.iter().nth(chunk_idx) {
                Some(sth) => &sth,
                None => break,
            };
            
            prev_bytes.extend(guessed_bytes.clone());
            
            let guessed_byte: Option<u8> = guess_next_byte_brute_force(&encryptor, &prev_bytes, ciphertext_chunk, chunk_idx, num_blocks_to_skip);
            match guessed_byte {
                Some(sth) => guessed_bytes.push(sth),
                None => break,
            }
        }
    }
    guessed_bytes
}

pub fn aes_ecb_encryptor_decryptor_factory() -> (impl Fn(&Vec<u8>) -> Vec<u8>, impl Fn(&Vec<u8>) -> Vec<u8>) {
    let random_key: Vec<u8> = generate_random_bytevec(16usize);
    let key_cloned: Vec<u8> = random_key.clone();
    let encryptor = move |plaintext: &Vec<u8>| -> Vec<u8> {
        aes_ecb_encrypt(plaintext, &random_key)
    };
    let decryptor = move |ciphertext: &Vec<u8>| -> Vec<u8> {
        decrypt_aes_ecb(ciphertext, &key_cloned)
    };
    (encryptor, decryptor)
}

pub fn aes_cbc_encryptor_decryptor_factory() -> (impl Fn(&Vec<u8>) -> Vec<u8>, impl Fn(&Vec<u8>) -> Vec<u8>, Vec<u8>) {
    let random_key: Vec<u8> = generate_random_bytevec(16usize);
    let random_iv: Vec<u8> = generate_random_bytevec(16usize);
    let key_cloned: Vec<u8> = random_key.clone();
    let iv_cloned: Vec<u8> = random_iv.clone();
    let iv_cloned_cloned: Vec<u8> = iv_cloned.clone();

    let encryptor = move |plaintext: &Vec<u8>| -> Vec<u8> {
        aes_cbc_encrypt(plaintext, &random_iv, &random_key)
    };
    let decryptor = move |ciphertext: &Vec<u8>| -> Vec<u8> {
        aes_cbc_decrypt(ciphertext, &iv_cloned, &key_cloned)
    };
    (encryptor, decryptor, iv_cloned_cloned)
}

pub fn find_matching_byteval(padding_oracle: &dyn Fn(&Vec<u8>) -> bool, ciphertext_arg: &Vec<u8>, pos: usize) -> Result<u8, Error> {
    let mut ciphertext: Vec<u8> = ciphertext_arg.clone();

    for count in 0..=255u8 {
        ciphertext[pos] = count;
        if !padding_oracle(&ciphertext) {
            continue;
        }
        if pos == 15 {
            ciphertext[pos-1] >>= 1;
            if padding_oracle(&ciphertext) {
                return Ok(count);
            }
            ciphertext[pos-1] = ciphertext_arg[pos-1];
            continue;
        }
        return Ok(count);
    }
    return Err(Error::NoMatchFound);
}

pub fn decrypt_cbc_block_padding_oracle(iv: &Vec<u8>, block: &Vec<u8>, padding_oracle: &dyn Fn(&Vec<u8>) -> bool) -> Result<Vec<u8>, Error> {
    let mut zeroing_iv = Vec::<u8>::new();
    let mut matching_byteval: u8;
    let mut ciphertext: Vec<u8> = iv.clone();

    ciphertext.extend(block.clone());
    let mut ciphertext_clone = ciphertext.clone();

    let ciphertext_len: usize = ciphertext.len();
    
    for pos in 1..=16usize {
        for (count, val) in zeroing_iv.iter().enumerate() {
            ciphertext_clone[ciphertext_len - 17 - count] = pos as u8 ^ val;
        }
        matching_byteval = match find_matching_byteval(&padding_oracle, &ciphertext_clone, ciphertext_len - 16 - pos) {
            Ok(sth) => sth,
            Err(_) => return Err(Error::DecryptionError),
        };
        zeroing_iv.push(pos as u8 ^ matching_byteval);
    }

    ciphertext_clone = ciphertext.clone();

    Ok(zip(zeroing_iv.iter().rev(), ciphertext_clone.iter())
        .map(|(val1, val2)| val1 ^ val2) 
        .collect())
}

pub fn aes_ctr_decrypt(ciphertext: &Vec<u8>, key: &Vec<u8>, nonce: &Vec<u8>) -> Vec<u8> {
    let mut plaintext_chunks = Vec::<Vec<u8>>::new();
    for (ctr, chunk) in ciphertext.chunks(16).enumerate() {
        let mut ctr_vec = vec![0u8; 8];
        let ctr_cnv: Vec<u8> = hextobytearray(&u8tohex(&(ctr as u8)));
        ctr_vec[0..ctr_cnv.len()].copy_from_slice(&ctr_cnv);
        let plaintext_chunk = decrypt_aes_ctr_block(&chunk.to_vec(), &key, &nonce, &ctr_vec);
        match strip_pkcs7_padding(&plaintext_chunk) {
            Ok(sth) => plaintext_chunks.push(sth),
            Err(_) => plaintext_chunks.push(plaintext_chunk),
        };
    }
    plaintext_chunks.into_iter().flatten().collect()
}

fn decrypt_aes_ctr_block(ciphertext_block: &Vec<u8>, key: &Vec<u8>, nonce: &Vec<u8>, ctr: &Vec<u8>) -> Vec<u8> {
    let mut to_encrypt: Vec<u8> = nonce.clone();
    to_encrypt.extend(ctr.clone());
    let enc_ctr: Vec<u8> = aes_ecb_encrypt(&to_encrypt, key);
    zip(enc_ctr.iter(), ciphertext_block.iter())
        .map(|(val1, val2)| val1 ^ val2)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decrypt_aes_ecb() {
        let ciphertext: Vec<u8> = vec![9, 18, 48, 170, 222, 62, 179, 48, 219, 170, 67, 88, 248, 141, 42, 108];
        let key: Vec<u8> = String::from("YELLOW SUBMARINE").as_bytes().to_vec();
        let plaintext: Vec<u8> = vec![73, 39, 109, 32, 98, 97, 99, 107, 32, 97, 110, 100, 32, 73, 39, 109];
        assert_eq!(&decrypt_aes_ecb(&ciphertext, &key), &plaintext);
    }

    #[test]
    fn test_aes_ecb_encryption() {
        let key: Vec<u8> = b"YELLOW SUBMARINE".to_vec();
        let plaintext: Vec<u8> = b"I'm back and I'm".to_vec();
        let ciphertext: Vec<u8> = vec![9, 18, 48, 170, 222, 62, 179, 48, 219, 170, 67, 88, 248, 141, 42, 108];
        assert_eq!(aes_ecb_encrypt(&plaintext, &key), ciphertext);
    }

    #[test]
    fn test_aes_cbc_decryption() {
        let key: Vec<u8> = b"YELLOW SUBMARINE".to_vec();
        let ciphertext: Vec<u8> = vec![9, 18, 48, 170, 222, 62, 179, 48, 219, 170, 67, 88, 248, 141, 42, 108];
        let iv: Vec<u8> = b"\x00".to_vec().repeat(16);
        let plaintext: Vec<u8> = b"I'm back and I'm".to_vec();
        assert_eq!(aes_cbc_decrypt(&ciphertext, &iv, &key), plaintext);
    }

    #[test]
    fn test_aes_cbc_encrypt() {
        let plaintext: Vec<u8> = b"hello world! this is my plaintex".to_vec();
        let ciphertext_expected: Vec<u8> = hextobytearray(&String::from("c7fe247ef97b21f07cbdd26cb5d346bfd27867cb00d9486723e159978fb9a5f9"));
        
        let key: Vec<u8> = b"\x42".to_vec().repeat(16);
        let iv: Vec<u8> = b"\x24".to_vec().repeat(16);
        let ciphertext: Vec<u8> = aes_cbc_encrypt(&plaintext, &iv, &key);
        let decrypted: Vec<u8> = aes_cbc_decrypt(&ciphertext, &iv, &key);

        assert_eq!(ciphertext, ciphertext_expected);
        assert_eq!(decrypted, plaintext);
    }
}
