/// sha1hash library
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


use vecofbits::BitVec;
use bytearrayconversion::bytearraytohex;

mod helpers;

pub use helpers::*;

// Constants for the SHA1 algorithm
const H0: u32 = 0x67452301;
const H1: u32 = 0xEFCDAB89;
const H2: u32 = 0x98BADCFE;
const H3: u32 = 0x10325476;
const H4: u32 = 0xC3D2E1F0;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha1() {
        let message1 = BitVec::new_from_bytearray(&b"The quick brown fox jumps over the lazy dog".to_vec());
        let expected1 = "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12".to_string();
        assert_eq!(sha1(&message1), expected1);
        
        let message2 = BitVec::new_from_bytearray(&b"The quick brown fox jumps over the lazy dog and searches for its new prey among the bushes in the jungle where lots and lots of animals spend their time living together".to_vec());
        let expected2 = "6a7c31734885d4364496fa7a1e68ee62e592dfe6".to_string();
        assert_eq!(sha1(&message2), expected2);
    }
}
