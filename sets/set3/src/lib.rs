/// Set 3 library functions

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

use std::iter::*;
use std::time::{ SystemTime, UNIX_EPOCH };

use aescipher::{generate_random_bytevec, aes_ctr_decrypt};
use mersennetwister::MT19937Gen;

pub fn get_unix_timestamp() -> u64 {
    let now = SystemTime::now();
    let duration_since_epoch = now.duration_since(UNIX_EPOCH).expect("Time cannot go backwards.");
    duration_since_epoch.as_secs()
}

pub fn check_valid_pkcs7_padding(ciphertext: &Vec<u8>) -> bool {
    let block: Vec<&u8> = ciphertext.iter().skip(ciphertext.len()-16).take(16).collect();
    let last_byte: &u8 = block.iter().last().unwrap();
    let mut iterator = block.iter().rev();
    let mut count = 0;
    while let Some(byteval) = iterator.next() {
        if **byteval != *last_byte {
            break;
        }
        count += 1;
    }
    if count <= block.len() && count as u8 == *last_byte {
        return true;
    }
    return false;
}

pub fn mt19937_keystream_encrypt(text: &Vec<u8>, key: &u16) -> Vec<u8> {
    let mut rng = MT19937Gen::new(*key as u32);
    text
        .iter()
        .map(|el| el ^ ((rng.gen() & 0xFF) as u8))
        .collect()
}

pub fn get_ctr_encryptor() -> impl Fn(&Vec<u8>) -> Vec<u8> {
    let key = generate_random_bytevec(16);
    let nonce = b"\x00".repeat(16).to_vec();
    let dumb_ctr_encryptor = move |plaintext: &Vec<u8>| -> Vec<u8> {
        aes_ctr_decrypt(plaintext, &key, &nonce)
    };
    return dumb_ctr_encryptor;
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_check_valid_pkcs7_padding() {
        let block: Vec<u8> = vec![10, 2, 32, 13, 11, 197, 6, 22, 8, 8, 8, 8, 8, 8, 8, 8];
        let block_2: Vec<u8> = vec![10, 2, 32, 13, 11, 197, 6, 22, 7, 7, 7, 7, 7, 7, 1, 1];
        assert!(check_valid_pkcs7_padding(&block));
        assert!(!check_valid_pkcs7_padding(&block_2));
    }
}
