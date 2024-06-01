use set1::*;
use rand::prelude::*;
use std::collections::HashMap;
use itertools::{Itertools, EitherOrBoth::*};
use aes::Aes128;
use aes::cipher::{
    BlockEncrypt, KeyInit,
    generic_array::GenericArray,
};

#[derive(Debug, PartialEq)]
pub enum Error {
    NoPadSpace,
    NoPadBytesFound,
}

pub fn format_chunks(vec: &Vec<u8>) {
    let string: String = bytearraytohex(&vec.clone());
    for chunk in string.as_bytes().chunks(32) {
        println!("{}", String::from_utf8(chunk.to_vec()).unwrap());
    }
}

pub fn generate_random_bytevec(size: usize) -> Vec<u8> {
    if size > 256 {
        panic!("Size cannot exceed 256.");
    }
    let mut rng = rand::thread_rng();
    let mut nums: Vec<u8> = (0u8..=255u8).collect();
    nums.shuffle(&mut rng);
    nums[0..size].to_vec()
}

pub fn pad_pkcs7(block: &Vec<u8>, block_length: usize) -> Result<Vec<u8>, Error> {
    if block.len() >= block_length {
        return Err(Error::NoPadSpace);
    }
    let mut res = block.clone();
    res.extend_from_slice(&vec![(block_length - block.len()) as u8].repeat(block_length - block.len()));
    Ok(res)
}

pub fn strip_pkcs7_padding(block: &Vec<u8>) -> Result<Vec<u8>, Error> {
    let last_byte: &u8 = block.iter().last().unwrap();
    let mut iterator = block.iter().rev();
    let mut count = block.len() + 1;
    while let Some(byteval) = iterator.next() {
        if *byteval != *last_byte {
            break;
        }
        count -= 1;
    }
    if count == block.len() {
        return Err(Error::NoPadBytesFound);
    } else {
        Ok(block[..(count - 1)].to_vec())
    }
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

pub fn pad_random_bytes(plaintext: &Vec<u8>) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let padding_size_prefix: usize = (5.0 * (1.0 + rng.gen::<f32>())) as usize;
    let padding_size_suffix: usize = (5.0 * (1.0 + rng.gen::<f32>())) as usize;
    let mut padded_plaintext: Vec<u8> = plaintext.clone();

    padded_plaintext.splice(0..0, (generate_random_bytevec(padding_size_prefix))[..].iter().cloned());
    padded_plaintext.splice(padded_plaintext.len()..padded_plaintext.len(), (generate_random_bytevec(padding_size_suffix))[..].iter().cloned());

    padded_plaintext
}

pub fn random_aes_encryptor(plaintext: &Vec<u8>, reveal: bool) -> Vec<u8> {
    let random_key: Vec<u8> = generate_random_bytevec(16usize);
    let random_iv: Vec<u8> = generate_random_bytevec(16usize);
    let mut rng = rand::thread_rng();
    let coinflip: f32 = rng.gen();
    
    // Pad plaintext
    let padded_plaintext: Vec<u8> = pad_random_bytes(&plaintext);
    
    // Encrypt!
    if coinflip > 0.5 {
        if reveal {
            println!("Encrypting using ECB!");
        }
        aes_ecb_encrypt(&padded_plaintext, &random_key)
    } else {
        if reveal {
            println!("Encrypting using CBC!");
        }
        aes_cbc_decrypt(&padded_plaintext, &random_iv, &random_key)
    }
}

pub fn encryption_oracle(ciphertext: &Vec<u8>) {
    if detect_aes_ecb_encryption(&bytearraytohex(ciphertext)) == 0 {
        println!("Ciphertext is AES CBC encrypted.");
    } else {
        println!("Ciphertext is AES ECB encrypted.");
    }
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

pub fn parse_key_value(string: &str) -> Option<HashMap<String, String>> {
    let res: Vec<&str> = string.split("&").collect();
    if res.len() == 1 {
        return None;
    }
    let parts: Vec<Option<(&str, &str)>> = res
                                    .iter()
                                    .map(|part| part.split_once("="))
                                    .collect();
    if parts.iter().all(|&x| x.is_some()) {
        let mut dict = HashMap::<String, String>::new();
        for part in parts {
            let (k, v): (&str, &str) = part.unwrap();
            dict.insert(k.to_string(), v.to_string());
        }
        return Some(dict);
    } else {
        return None;
    }
}

pub fn profile_for(email: &String) -> String {
    let mut rng = rand::thread_rng();
    let uid: u32 = (rng.gen::<f32>() as f32 * 100.0) as u32;
    let email_clone: String = email.replace("&", "").replace("=", "");
    format!("email={}&uid={}&role=user", email_clone, uid)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pad_pkcs7() {
        let block: Vec<u8> = b"Pigs are fly".to_vec();
        assert_eq!((pad_pkcs7(&block, 16)).unwrap().len(), 16);
        assert_eq!((pad_pkcs7(&block, 16)).unwrap(), b"Pigs are fly\x04\x04\x04\x04");
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
    fn test_generate_random_bytevec() {
        assert_eq!((generate_random_bytevec(16usize)).len(), 16usize);
    }

    #[test]
    fn test_random_aes_encryptor() {
        let plaintext: Vec<u8> = b"We all live in a yellow submarine.".to_vec();
        assert!((random_aes_encryptor(&plaintext, false)).len() > 0);
    }

    #[test]
    fn test_pad_random_bytes() {
        let text_to_pad: Vec<u8> = generate_random_bytevec(128usize);
        let padded_text: Vec<u8> = pad_random_bytes(&text_to_pad);
        assert!(text_to_pad.len() + 10 <=  padded_text.len());
        assert!(text_to_pad.len() + 20 >=  padded_text.len());
    }

    #[test]
    fn test_key_value_parser() {
        let test_string = "foo=bar&baz=qux&zap=zazzle";
        let expected = HashMap::from([
            ("foo".to_string(), "bar".to_string()), ("baz".to_string(), "qux".to_string()), 
            ("zap".to_string(), "zazzle".to_string())
        ]);
        assert_eq!(parse_key_value(&test_string), Some(expected));

        let test_string_2 = "foo=bar&bazqux&zap=zazzle";
        assert_eq!(parse_key_value(&test_string_2), None);
    }

    #[test]
    fn test_profile_for() {
        let profile: String = profile_for(&"you@example.com".to_string());
        let parsed = parse_key_value(&profile.as_str()).unwrap();
        assert_eq!(parsed["email"], String::from("you@example.com"));
        assert_eq!(parsed["role"], String::from("user"));
    }

    #[test]
    fn test_strip_pkcs7_padding() {
        let bytes: Vec<u8> = b"Bytes are fun!\xae\xae\xae\xae\xae".to_vec();
        assert_eq!(strip_pkcs7_padding(&bytes).unwrap(), b"Bytes are fun!".to_vec());
        
        let bytes_no_padding: Vec<u8> = b"ICE ICE BABY\x01\x02\x03\x04".to_vec();
        assert_eq!(strip_pkcs7_padding(&bytes_no_padding), Err(Error::NoPadBytesFound));
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
