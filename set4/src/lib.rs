use std::{thread, time::Duration};
use itertools::{Itertools, EitherOrBoth::*};
use serde::Deserialize;
use axum::http::StatusCode;
use http_body_util::Empty;
use hyper::{ Request, body::Bytes };
use tokio::time::Instant;
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;

use std::iter::*;
use set1::*;
use set2::*;
use set3::*;

// Constants for the SHA1 algorithm
const H0: u32 = 0x67452301;
const H1: u32 = 0xEFCDAB89;
const H2: u32 = 0x98BADCFE;
const H3: u32 = 0x10325476;
const H4: u32 = 0xC3D2E1F0;

// Constants for the MD4 algorithm
const MD4_A: u32 = 0x67452301;
const MD4_B: u32 = 0xEFCDAB89;
const MD4_C: u32 = 0x98BADCFE;
const MD4_D: u32 = 0x10325476;

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

#[derive(Debug, PartialEq)]
pub enum BitVecError {
    Overflow(usize)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BitVec {
    data: Vec<u8>,
}

impl BitVec {
    pub fn new(size_arg: usize) -> BitVec {
        BitVec{ data: Vec::<u8>::with_capacity(size_arg) }
    }

    pub fn new_from_num(size_arg: usize, num: &u32) -> BitVec {
        if size_arg % 8 > 0 {
            panic!("Bit vector size must be multiple of 8.")
        }
        let mut res = BitVec{ data: vec![0x00u8; size_arg] };
        res.populate(num);
        res
    }

    pub fn new_from_bytearray(bytearr: &Vec<u8>) -> BitVec {
        let mut vec = BitVec::new(bytearr.len()*8);
        let data: Vec<u8> = bytearr
                            .iter()
                            .map(|byte| BitVec::new_from_num(8, &(*byte as u32)).get_data().clone())
                            .flatten()
                            .collect();
        vec.extend(data);
        vec
    }

    pub fn populate(&mut self, num: &u32) {
        self.data = (0..(self.data.len() as u32))
            .rev()
            .map(|ctr| num & (1 << ctr))
            .map(|val| if val > 0 { 0x01 } else { 0x00 })
            .collect();
    }

    pub fn get_data(&self) -> &Vec<u8> {
        &self.data
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn push(&mut self, bit: u8) {
        if bit != 0x01u8 && bit != 0x00u8 {
            panic!("Cannot push non-bit character.");
        }
        self.data.push(bit);
    }

    pub fn extend(&mut self, bitvec: Vec<u8>) {
        for bit in bitvec.iter() {
            if *bit != 0x01u8 && *bit != 0x00u8 {
                panic!("Cannot push non-bit character.")
            }
        }
        self.data.extend(bitvec);
    }

    pub fn to_num(&self) -> Result<u32, BitVecError> {
        if self.data.len() > 32 {
            Err(BitVecError::Overflow(self.data.len()))
        } else {
            Ok(self.data
                .iter()
                .enumerate()
                .map(|(ctr, x)| *x as u32 * ((1 << (self.data.len()-ctr-1)) as u32))
                .sum())
        }
    }

    pub fn to_bytearray(&self) -> Vec<u8> {
        self.data
                .chunks(8)
                .map(|chunk| chunk.iter().enumerate().map(|(ctr, x)| *x as u8 * ((1 << (8-ctr-1)) as u8)).sum())
                .collect()
    }

    pub fn left_shift(&mut self, places: usize) {
        self.data.extend(vec![0x00u8; places])
    }

    pub fn bitwise_or(&self, other: &BitVec) -> BitVec {
        let res: Vec<u8> = self.data.iter().rev().zip_longest(other.get_data().iter().rev())
            .map(|pair| match pair {
                    Both(l, r) => l | r,
                    Left(l) => *l,
                    Right(r) => *r
             })
            .rev()
            .collect();
        let mut res_bitvec = BitVec::new(std::cmp::max(self.len(), other.len()));
        res_bitvec.extend(res);
        res_bitvec
    }
}

pub fn u32_rotate_left(num: &u32, mut places: usize) -> u32 {
    places &= 32 - 1;
    if places == 0 {
        return num.clone();
    }
    return (num << places) | (num >> (32 - places));
}

pub fn u32_rotate_right(num: &u32, mut places: usize) -> u32 {
    places &= 32 - 1;
    if places == 0 {
        return num.clone();
    }
    return (num >> places) | (num << (32 - places));
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

pub fn compute_md_padding_sha1(message_len: usize) -> BitVec {
    let m1: u64 = message_len as u64;        // Message length in bits
    
    let mut res = BitVec::new(0);
    
    // Preprocessing
    if m1 % 8 == 0 {
        res.push(0x01u8);
    }
    let k: usize = 512 - ((m1 as usize + 1) % 512) - 64;
    res.extend(vec![0x00u8; k]);

    // Convert m1 to bitvec and then append to message
    let mut m1_bitvec = BitVec::new_from_num(32, &((m1 & 0xFFFFFFFF) as u32));
    let mut higher_bits = BitVec::new_from_num(32, &(((m1 >> 32) & 0xFFFFFFFF) as u32));
    higher_bits.left_shift(32);
    m1_bitvec = m1_bitvec.bitwise_or(&higher_bits);
    res.extend(m1_bitvec.get_data().clone());
    
    res
}

pub fn compute_md_padding_md4(message_len: usize) -> BitVec {
    let m1: u64 = message_len as u64;        // Message length in bits
    
    let mut res = BitVec::new(0);
    
    // Preprocessing
    if m1 % 8 == 0 {
        res.extend(vec![0x01u8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    }
    let x: i64 = 512 - ((m1 as i64 + 8) % 512) - 64;
    let k: usize = if x < 0 {
        (x + 512) as usize
    } else {
        x as usize
    };
    res.extend(vec![0x00u8; k]);

    // Convert m1 to bitvec and then append to message
    let mut m1_bitvec = BitVec::new_from_num(8, &((m1 & 0xFF) as u32));
    for ctr in 1..8 {
        m1_bitvec.extend(BitVec::new_from_num(8, &(((m1 >> (8 * ctr)) & 0xFF) as u32)).get_data().clone());
    }
    res.extend(m1_bitvec.get_data().clone());
    
    res
}

pub fn sha1_hash(message: &BitVec, hash_1: &u32, hash_2: &u32, hash_3: &u32, hash_4: &u32, hash_5: &u32) -> BitVec {
    // Hash values
    let mut h0: u32 = hash_1.clone(); 
    let mut h1: u32 = hash_2.clone(); 
    let mut h2: u32 = hash_3.clone(); 
    let mut h3: u32 = hash_4.clone(); 
    let mut h4: u32 = hash_5.clone(); 

    // Processing
    for chunk in message.get_data().chunks(512) {
        // Break chunk into 16 32-bit words
        let mut words: Vec<u32> = chunk
                                    .chunks(32)
                                    .map(|x| {
                                        let mut val = BitVec::new(32);
                                        val.extend(x.to_vec());
                                        val.to_num().unwrap() as u32
                                    })
                                    .collect();
        
        // Extend words from 16 to 80
        for count in 16..80 {
            let res = (words[count-3] ^ words[count-8]) ^ (words[count-14] ^ words[count-16]);
            words.push(u32_rotate_left(&res, 1));
        }

        // Initialize hash values for this chunk
        let mut a: u32 = h0.clone();
        let mut b: u32 = h1.clone();
        let mut c: u32 = h2.clone();
        let mut d: u32 = h3.clone();
        let mut e: u32 = h4.clone();
        let mut f: u32;
        let mut k: u32;
        
        // Main loop
        for count in 0..80 {
            match count {
                0..=19 => {
                    f = (b & c) | (!b & d);
                    k = 0x5A827999;
                },
                20..=39 => {
                    f = b ^ c ^ d;
                    k = 0x6ED9EBA1;
                },
                40..=59 => {
                    f = (b & c) | (b & d) | (c & d);
                    k = 0x8F1BBCDC;
                },
                60..=79 => {
                    f = b ^ c ^ d;
                    k = 0xCA62C1D6;
                }
                _ => continue,
            }
            let tmp: u32 = ((u32_rotate_left(&a, 5) as u64 + f as u64 + e as u64 + k as u64 + words[count] as u64) & 0xFFFFFFFF) as u32;
            e = d.clone();
            d = c.clone();
            c = u32_rotate_left(&b, 30);
            b = a.clone();
            a = tmp;
        }

        // Add to overall hashes
        h0 = ((h0 as u64 + a as u64) & 0xFFFFFFFF) as u32;
        h1 = ((h1 as u64 + b as u64) & 0xFFFFFFFF) as u32;
        h2 = ((h2 as u64 + c as u64) & 0xFFFFFFFF) as u32;
        h3 = ((h3 as u64 + d as u64) & 0xFFFFFFFF) as u32;
        h4 = ((h4 as u64 + e as u64) & 0xFFFFFFFF) as u32;
    }

    // Produce final hash
    let mut h0_vec = BitVec::new_from_num(32, &h0);
    let mut h1_vec = BitVec::new_from_num(32, &h1);
    let mut h2_vec = BitVec::new_from_num(32, &h2);
    let mut h3_vec = BitVec::new_from_num(32, &h3);
    let h4_vec = BitVec::new_from_num(32, &h4);
    
    h0_vec.left_shift(128);
    h1_vec.left_shift(96);
    h2_vec.left_shift(64);
    h3_vec.left_shift(32);

    h0_vec.bitwise_or(&h1_vec.bitwise_or(&h2_vec.bitwise_or(&h3_vec.bitwise_or(&h4_vec))))
}

pub fn sha1(message_arg: &BitVec) -> String {
    let mut message: BitVec = message_arg.clone();

    // Preprocessing
    message.extend(compute_md_padding_sha1(message_arg.len()).get_data().clone());

    // Processing
    let hh: BitVec = sha1_hash(&message, &H0, &H1, &H2, &H3, &H4);

    bytearraytohex(&hh.to_bytearray())
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

fn md4_f(x: &u32, y: &u32, z: &u32) -> u32 {
    (x & y) | (!x & z)
}

fn md4_g(x: &u32, y: &u32, z: &u32) -> u32 {
    (x & y) | (x & z) | (y & z)
}

fn md4_h(x: &u32, y: &u32, z: &u32) -> u32 {
    x ^ y ^ z
}

pub fn md4_hash(message: &BitVec, hash1: &u32, hash2: &u32, hash3: &u32, hash4: &u32) -> BitVec {
    let mut a: u32 = hash1.clone();
    let mut b: u32 = hash2.clone();
    let mut c: u32 = hash3.clone();
    let mut d: u32 = hash4.clone();
    
    for chunk in message.get_data().chunks(512) {
        // Break chunk into 16 32-bit words
        let words: Vec<u32> = chunk
                                    .chunks(32)
                                    .map(|x| {
                                        let mut val = BitVec::new(32);
                                        val.extend(x.to_vec());
                                        BitVec::new_from_bytearray(&val.to_bytearray()
                                                                       .into_iter()
                                                                       .rev()
                                                                       .collect::<Vec<u8>>()).to_num().unwrap() as u32
                                    })
                                    .collect();
        
        let aa: u32 = a.clone();
        let bb: u32 = b.clone();
        let cc: u32 = c.clone();
        let dd: u32 = d.clone();
        
        // Round 1
        let mut idxs: Vec<usize> = vec![3usize, 7, 11, 19];
        for k in 0..4usize {
            a = u32_rotate_left(&(((a as u64 + md4_f(&b, &c, &d) as u64 + words[4*k] as u64) & 0xFFFFFFFF) as u32), idxs[0].clone());
            d = u32_rotate_left(&(((d as u64 + md4_f(&a, &b, &c) as u64 + words[4*k+1] as u64) & 0xFFFFFFFF) as u32), idxs[1].clone());
            c = u32_rotate_left(&(((c as u64 + md4_f(&d, &a, &b) as u64 + words[4*k+2] as u64) & 0xFFFFFFFF) as u32), idxs[2].clone());
            b = u32_rotate_left(&(((b as u64 + md4_f(&c, &d, &a) as u64 + words[4*k+3] as u64) & 0xFFFFFFFF) as u32), idxs[3].clone());
        }


        // Round 2
        idxs = vec![3usize, 5, 9, 13];
        for k in 0..4usize {
            a = u32_rotate_left(&(((a as u64 + md4_g(&b, &c, &d) as u64 + words[k] as u64 + 0x5A827999u64) & 0xFFFFFFFF) as u32), idxs[0].clone());
            d = u32_rotate_left(&(((d as u64 + md4_g(&a, &b, &c) as u64 + words[k+4] as u64 + 0x5A827999u64) & 0xFFFFFFFF) as u32), idxs[1].clone());
            c = u32_rotate_left(&(((c as u64 + md4_g(&d, &a, &b) as u64 + words[k+8] as u64 + 0x5A827999u64) & 0xFFFFFFFF) as u32), idxs[2].clone());
            b = u32_rotate_left(&(((b as u64 + md4_g(&c, &d, &a) as u64 + words[k+12] as u64 + 0x5A827999u64) & 0xFFFFFFFF) as u32), idxs[3].clone());
        }

        
        // Round 3
        idxs = vec![3usize, 9, 11, 15];
        for k in vec![0usize, 2, 1, 3].iter() {
            a = u32_rotate_left(&(((a as u64 + md4_h(&b, &c, &d) as u64 + words[*k] as u64 + 0x6ED9EBA1u64) & 0xFFFFFFFF) as u32), idxs[0].clone());
            d = u32_rotate_left(&(((d as u64 + md4_h(&a, &b, &c) as u64 + words[k+8] as u64 + 0x6ED9EBA1u64) & 0xFFFFFFFF) as u32), idxs[1].clone());
            c = u32_rotate_left(&(((c as u64 + md4_h(&d, &a, &b) as u64 + words[k+4] as u64 + 0x6ED9EBA1u64) & 0xFFFFFFFF) as u32), idxs[2].clone());
            b = u32_rotate_left(&(((b as u64 + md4_h(&c, &d, &a) as u64 + words[k+12] as u64 + 0x6ED9EBA1u64) & 0xFFFFFFFF) as u32), idxs[3].clone());
        }
        
        // Increment all four registers
        a = ((a as u64 + aa as u64) & 0xFFFFFFFF) as u32;
        b = ((b as u64 + bb as u64) & 0xFFFFFFFF) as u32;
        c = ((c as u64 + cc as u64) & 0xFFFFFFFF) as u32;
        d = ((d as u64 + dd as u64) & 0xFFFFFFFF) as u32;
        
    }
    
    // Produce final hash
    let mut a_vec: Vec<u8> = BitVec::new_from_num(32, &a).to_bytearray().into_iter().rev().collect();
    let b_vec: Vec<u8> = BitVec::new_from_num(32, &b).to_bytearray().into_iter().rev().collect();
    let c_vec: Vec<u8> = BitVec::new_from_num(32, &c).to_bytearray().into_iter().rev().collect();
    let d_vec: Vec<u8> = BitVec::new_from_num(32, &d).to_bytearray().into_iter().rev().collect();
    
    a_vec.extend(b_vec);
    a_vec.extend(c_vec);
    a_vec.extend(d_vec);
    
    BitVec::new_from_bytearray(&a_vec)
}

pub fn md4(message_arg: &BitVec) -> String {
    let mut message: BitVec = message_arg.clone();

    // Preprocessing
    message.extend(compute_md_padding_md4(message_arg.len()).get_data().clone());
 
    // Processing
    let hash: BitVec = md4_hash(&message, &MD4_A, &MD4_B, &MD4_C, &MD4_D);
    
    bytearraytohex(&hash.to_bytearray())
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

fn compute_blocksized_key(key: &Vec<u8>, blocksize: &usize, hashfunc: &impl Fn(&BitVec) -> String) -> Vec<u8> {
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
    fn test_bitvec_bytearray_conversion() {
        let bytearr: Vec<u8> = b"Cowabunga".to_vec();
        assert_eq!(BitVec::new_from_bytearray(&bytearr).to_bytearray(), bytearr);
    }

    #[test]
    fn test_bitvec_number_conversion() {
        let number: u32 = 0xFEEDBEEF;
        assert_eq!(BitVec::new_from_num(32, &number).to_num().unwrap(), number);
    }

    #[test]
    fn test_bitvec_left_shift() {
        let mut bitvec = BitVec::new_from_num(8, &0x80);
        bitvec.left_shift(8);
        assert_eq!(bitvec, BitVec::new_from_num(16, &0x8000));
    }

    #[test]
    fn test_bitvec_bitwise_or() {
        let mut bitvec = BitVec::new_from_num(8, &0x80);
        bitvec.left_shift(8);
        assert_eq!(bitvec.bitwise_or(&BitVec::new_from_num(8, &0x80)), BitVec::new_from_num(16, &0x8080));
    }

    #[test]
    fn test_sha1() {
        let message1 = BitVec::new_from_bytearray(&b"The quick brown fox jumps over the lazy dog".to_vec());
        let expected1 = "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12".to_string();
        assert_eq!(sha1(&message1), expected1);
        
        let message2 = BitVec::new_from_bytearray(&b"The quick brown fox jumps over the lazy dog and searches for its new prey among the bushes in the jungle where lots and lots of animals spend their time living together".to_vec());
        let expected2 = "6a7c31734885d4364496fa7a1e68ee62e592dfe6".to_string();
        assert_eq!(sha1(&message2), expected2);
    }

    #[test]
    fn test_xor_bytearrays() {
        let arr1: Vec<u8> = b"How do you do?".to_vec();
        let arr2: Vec<u8> = b"Gibberish stuf".to_vec();
        assert_eq!(xor_bytearrays(&arr1, &arr2), Ok(zip(arr1.iter(),arr2.iter()).map(|(a, b)| a ^ b).collect::<Vec<u8>>()));
    }

    #[test]
    fn test_u32_rotate_left() {
        let num: u32 = 1;
        assert_eq!(u32_rotate_left(&num, 1), (1 << 1) as u32);
    }

    #[test]
    fn test_u32_rotate_right() {
        let num: u32 = 1;
        assert_eq!(u32_rotate_right(&num, 1), (1 << 31) as u32);
    }

    #[test]
    fn test_bitvec() {
        let vec = BitVec::new_from_num(32, &0xABCDEFu32);
        assert_eq!(vec.get_data().clone(), vec![0u8, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 1, 1, 0, 1, 1, 1, 1]);
        assert_eq!(vec.to_num().unwrap(), 0xABCDEFu32);
    }

    #[test]
    fn test_md4() {
        let messages: Vec<Vec<u8>> = vec![
                                            b"a".to_vec(), 
                                            b"abc".to_vec(),
                                            b"message digest".to_vec(), 
                                            b"abcdefghijklmnopqrstuvwxyz".to_vec(),
                                            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".to_vec(),
                                            b"12345678901234567890123456789012345678901234567890123456789012345678901234567890".to_vec()
                                        ];
        let expected: Vec<String> = vec![
                                            "bde52cb31de33e46245e05fbdbd6fb24".to_string(), 
                                            "a448017aaf21d8525fc10ae87aa6729d".to_string(), 
                                            "d9130a8164549fe818874806e1c7014b".to_string(), 
                                            "d79e1c308aa5bbcdeea8ed63df412da9".to_string(), 
                                            "043f8582f241db351ce627e153e7f0e4".to_string(), 
                                            "e33b4ddc9c38f2199c3e7b164fcc0536".to_string()
                                        ];
        for (input, output) in zip(messages.iter(), expected.iter()) {
            assert_eq!(md4(&BitVec::new_from_bytearray(input)), *output);
        }
    }

    #[test]
    fn test_hmac_sha1() {
        let test_msg = b"The quick brown fox jumps over the lazy dog".to_vec();
        let test_key = b"key".to_vec();
        let expected = "de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9".to_string();
        assert_eq!(hmac_sha1(&test_msg, &test_key), expected);
    }
}
