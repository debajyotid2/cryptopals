/// Set 4 library functions
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




use std::{thread, time::Duration};
use serde::Deserialize;
use axum::http::StatusCode;
use http_body_util::Empty;
use hyper::{ Request, body::Bytes };
use tokio::time::Instant;
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;

use std::iter::*;
use bytearrayconversion::{bytearraytohex, hextobytearray};
use aescipher::{aes_ecb_encrypt, generate_random_bytevec, u8tohex};
use vecofbits::BitVec;
use sha1hash::{sha1, compute_md_padding_sha1, sha1_hash};
use md4hash::{md4, compute_md_padding_md4, md4_hash};

#[derive(Deserialize)]
pub struct FileInfo {
    pub file: String,
    pub signature: String
}

#[derive(Debug, Clone, PartialEq)]
struct RequestStatus {
    pub status: StatusCode,
    pub time_elapsed: u128,
}

#[derive(Debug, PartialEq)]
pub enum Error {
    OutOfKeystreamBounds,
    InvalidASCIIChars(Vec<u8>),
    DifferentArrayLengths(usize, usize),
    NotEnoughBits(usize),
}

pub fn check_ascii_chars(text: &Vec<u8>) -> Result<Vec<u8>, Error> {
    for byte in text.iter() {
        if *byte < 128 {
            continue;
        }
        return Err(Error::InvalidASCIIChars(text.clone()));
    }
    Ok(text.clone())
}

pub fn edit_ctr_ciphertext(ciphertext: &Vec<u8>, key: &Vec<u8>, offset: usize, newtext: &Vec<u8>) -> Result<Vec<u8>, Error> {
    if offset + newtext.len() > ciphertext.len() {
        return Err(Error::OutOfKeystreamBounds);
    }

    // Generate keystream
    let nonce: Vec<u8> = b"\x00".repeat(8).to_vec();
    let mut keystream = Vec::<u8>::new();
    for ctr in 0..(ciphertext.len() / 16 + 1) {
        let mut ctr_vec = vec![0u8; 8];
        let ctr_cnv: Vec<u8> = hextobytearray(&u8tohex(&(ctr as u8)));
        ctr_vec[0..ctr_cnv.len()].copy_from_slice(&ctr_cnv);

        let mut to_encrypt: Vec<u8> = nonce.clone();
        to_encrypt.extend(ctr_vec.clone());
        let enc_ctr: Vec<u8> = aes_ecb_encrypt(&to_encrypt, key);
        keystream.extend(enc_ctr);
    }
    
    let mut spliced_ciphertext = ciphertext.clone();
    let part: Vec<u8> = zip(newtext.iter(), keystream.iter().skip(offset).take(newtext.len()))
                            .map(|(a, b)| a ^ b)
                            .collect();
    spliced_ciphertext[offset..(offset + newtext.len())].copy_from_slice(&part[..]);
    Ok(spliced_ciphertext)
}

pub fn xor_bytearrays(arr1: &Vec<u8>, arr2: &Vec<u8>) -> Result<Vec<u8>, Error> {
    if arr1.len() != arr2.len() {
        return Err(Error::DifferentArrayLengths(arr1.len(), arr2.len()));
    }
    Ok(zip(arr1.iter(), arr2.iter()).map(|(a1, a2)| a1 ^ a2).collect())
}


pub fn sha1_length_extension_attack(message: &BitVec, mac: &String, custom_message: &BitVec, key_len: usize) -> String {
        let mac_bitvec = BitVec::new_from_bytearray(&hextobytearray(&mac));
        let new_hashes: Vec<u32> = mac_bitvec.get_data()
                            .clone()
                            .chunks(32)
                            .map(|chunk| { 
                                let mut res = BitVec::new(0);
                                res.extend(chunk.to_vec());
                                res.to_num().unwrap() as u32
                            })
                            .collect();
        let padding: BitVec = compute_md_padding_sha1(message.len() + key_len);
        let second_padding: BitVec = compute_md_padding_sha1(message.len() + key_len + custom_message.len() + padding.len());
        
        let mut new_message = custom_message.clone();
        new_message.extend(second_padding.get_data().clone());
        
        let new_mac = sha1_hash(&new_message, &new_hashes[0], &new_hashes[1], &new_hashes[2], &new_hashes[3], &new_hashes[4]);
        bytearraytohex(&new_mac.to_bytearray())
}

pub fn get_secret_prefix_sha1_mac_generator() -> impl Fn(&Vec<u8>) -> String {
    let key = generate_random_bytevec(16);
    let generate_mac = move |message: &Vec<u8>| -> String {
        let mut joined = key.clone();
        joined.extend(message.clone());
        sha1(&BitVec::new_from_bytearray(&joined))
    };
    generate_mac
}

pub fn md4_length_extension_attack(message: &BitVec, mac: &String, custom_message: &BitVec, key_len: usize) -> String {
        let mac_bytearr: Vec<u8> = hextobytearray(&mac);
        let new_hashes: Vec<u32> = mac_bytearr
                            .chunks(4)
                            .map(|chunk| { 
                                let res = BitVec::new_from_bytearray(&chunk.into_iter().rev().map(|x| *x).collect::<Vec<u8>>());
                                res.to_num().unwrap() as u32
                            })
                            .collect();
        let padding: BitVec = compute_md_padding_md4(message.len() + key_len);
        let second_padding: BitVec = compute_md_padding_md4(message.len() + key_len + custom_message.len() + padding.len());
        
        let mut new_message = custom_message.clone();
        new_message.extend(second_padding.get_data().clone());
        
        let new_mac = md4_hash(&new_message, &new_hashes[0], &new_hashes[1], &new_hashes[2], &new_hashes[3]);
        bytearraytohex(&new_mac.to_bytearray())
}

pub fn get_secret_prefix_md4_mac_generator() -> impl Fn(&Vec<u8>) -> String {
    let key = generate_random_bytevec(16);
    let generate_mac = move |message: &Vec<u8>| -> String {
        let mut joined = key.clone();
        joined.extend(message.clone());
        md4(&BitVec::new_from_bytearray(&joined))
    };
    generate_mac
}

pub fn compute_blocksized_key(key: &Vec<u8>, blocksize: &usize, hashfunc: &impl Fn(&BitVec) -> String) -> Vec<u8> {
    let mut key_bitvec = BitVec::new_from_bytearray(key);
    if key_bitvec.len() > *blocksize {
        key_bitvec = BitVec::new_from_bytearray(&hextobytearray(&hashfunc(&key_bitvec)));
    }
    key_bitvec.extend(vec![0x00u8; blocksize - key_bitvec.len()]);
    key_bitvec.to_bytearray()
}

pub fn hmac_sha1(message: &Vec<u8>, key: &Vec<u8>) -> String {
    let blocksize: usize = 512;
    let blocksized_key = compute_blocksized_key(key, &blocksize, &sha1);
    let mut o_key_pad = xor_bytearrays(&blocksized_key, &b"\x5c".repeat(blocksize / 8)).unwrap();
    let mut i_key_pad = xor_bytearrays(&blocksized_key, &b"\x36".repeat(blocksize / 8)).unwrap();

    i_key_pad.extend(message.clone());
    let res1 = hextobytearray(&sha1(&BitVec::new_from_bytearray(&i_key_pad)));
    o_key_pad.extend(res1);
    sha1(&BitVec::new_from_bytearray(&o_key_pad))
}

pub fn get_secret_key_sha1_hmac_generator() -> impl Fn(&Vec<u8>) -> String {
    let key = generate_random_bytevec(16);
    let generate_mac = move |message: &Vec<u8>| -> String {
        hmac_sha1(message, &key)
    };
    generate_mac
}

pub fn insecure_compare(incoming: &Vec<u8>, actual: &Vec<u8>) -> bool {
    for (b1, b2) in zip(incoming.iter(), actual.iter()) {
        if b1 != b2 {
            return false;
        }
        thread::sleep(Duration::from_millis(5));
    }
    true
}

async fn send_validation_request(url_string: &String) -> Result<RequestStatus, Box<dyn std::error::Error + Send + Sync>> {
    let url = url_string.as_str().parse::<hyper::Uri>()?;
    let host = url.host().expect("URI has no host.");
    let port = url.port_u16().unwrap_or(3000);
    let addr = format!("{}:{}", host, port);
    
    // Open a TCP connection to the remote
    let stream = TcpStream::connect(addr).await?;
    let io = TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;

    tokio::task::spawn(async move {
        if let Err(err) = conn.await {
            println!("Connection failed: {:?}", err);
        }
    });

    // Send GET request
    let authority = url.authority().unwrap().clone();
    let req = Request::builder()
                .uri(url)
                .header(hyper::header::HOST, authority.as_str())
                .body(Empty::<Bytes>::new())?;

    // Measure time to get response
    let now = Instant::now();
    let res = sender.send_request(req).await?;
    let elapsed = now.elapsed();
   
    Ok(RequestStatus{ status: res.status(), time_elapsed: elapsed.as_nanos() })
}

pub async fn hmac_sha1_timing_attack(filename: &String, host: &String, port: u16) -> String {
    let key = b"guess".to_vec();
    let mut signature_arr = hextobytearray(&hmac_sha1(&filename.as_bytes().to_vec(), &key));
    let mut found = false;
    for idx in 0..signature_arr.len() {
        if found { break; };
        let signature_orig = signature_arr.clone();
        let mut guessed_byte: u8 = 0;
        let mut max_time_elapsed_ns: u128 = 0;
        for byteval in 0..=255u8 {
            if byteval == signature_orig[idx] {
                continue;
            }
            signature_arr[idx] = byteval;
            
            let signature = bytearraytohex(&signature_arr);
            let status = send_validation_request(&format!("http://{}:{}/test?file={}&signature={}", host, port, filename, signature)).await.unwrap();
            
            if status.time_elapsed > max_time_elapsed_ns {
                guessed_byte = byteval;
                max_time_elapsed_ns = status.time_elapsed;
            }
            if status.status == StatusCode::OK {
                found = true;
                println!("Match found!");
                break;
            }
        }
        signature_arr[idx] = guessed_byte;
    }
    if !found {
        println!("Failed to break HMAC. Returning best guess ...");
    }
    bytearraytohex(&signature_arr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_ascii_chars() {
        let test_val: Vec<u8> = vec![123, 122, 121, 1, 3, 2];
        assert_eq!(check_ascii_chars(&test_val), Ok(test_val));
    }

    #[test]
    fn test_xor_bytearrays() {
        let arr1: Vec<u8> = b"How do you do?".to_vec();
        let arr2: Vec<u8> = b"Gibberish stuf".to_vec();
        assert_eq!(xor_bytearrays(&arr1, &arr2), Ok(zip(arr1.iter(),arr2.iter()).map(|(a, b)| a ^ b).collect::<Vec<u8>>()));
    }

    #[test]
    fn test_bitvec() {
        let vec = BitVec::new_from_num(32, &0xABCDEFu32);
        assert_eq!(vec.get_data().clone(), vec![0u8, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 1, 1, 0, 1, 1, 1, 1]);
        assert_eq!(vec.to_num().unwrap(), 0xABCDEFu32);
    }

    #[test]
    fn test_hmac_sha1() {
        let test_msg = b"The quick brown fox jumps over the lazy dog".to_vec();
        let test_key = b"key".to_vec();
        let expected = "de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9".to_string();
        assert_eq!(hmac_sha1(&test_msg, &test_key), expected);
    }
}
