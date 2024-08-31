/// Library functions for set2
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

use rand::prelude::*;
use std::collections::HashMap;
use bytearrayconversion::bytearraytohex;
use aescipher::{
    generate_random_bytevec, 
    aes_ecb_encrypt, 
    aes_cbc_decrypt, 
    detect_aes_ecb_encryption
};

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

#[cfg(test)]
mod tests {
    use super::*;

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
}
