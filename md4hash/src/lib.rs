use bytearrayconversion::bytearraytohex;
/// md4hash library
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
use std::iter::*;
use vecofbits::BitVec;

mod helpers;

pub use helpers::*;

// Constants for the MD4 algorithm
const MD4_A: u32 = 0x67452301;
const MD4_B: u32 = 0xEFCDAB89;
const MD4_C: u32 = 0x98BADCFE;
const MD4_D: u32 = 0x10325476;

pub fn compute_md_padding_md4(message_len: usize) -> BitVec {
    let m1: u64 = message_len as u64; // Message length in bits

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
        m1_bitvec.extend(
            BitVec::new_from_num(8, &(((m1 >> (8 * ctr)) & 0xFF) as u32))
                .get_data()
                .clone(),
        );
    }
    res.extend(m1_bitvec.get_data().clone());

    res
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
                BitVec::new_from_bytearray(
                    &val.to_bytearray().into_iter().rev().collect::<Vec<u8>>(),
                )
                .to_num()
                .unwrap() as u32
            })
            .collect();

        let aa: u32 = a.clone();
        let bb: u32 = b.clone();
        let cc: u32 = c.clone();
        let dd: u32 = d.clone();

        // Round 1
        let mut idxs: Vec<usize> = vec![3usize, 7, 11, 19];
        for k in 0..4usize {
            a = u32_rotate_left(
                &(((a as u64 + md4_f(&b, &c, &d) as u64 + words[4 * k] as u64) & 0xFFFFFFFF)
                    as u32),
                idxs[0].clone(),
            );
            d = u32_rotate_left(
                &(((d as u64 + md4_f(&a, &b, &c) as u64 + words[4 * k + 1] as u64) & 0xFFFFFFFF)
                    as u32),
                idxs[1].clone(),
            );
            c = u32_rotate_left(
                &(((c as u64 + md4_f(&d, &a, &b) as u64 + words[4 * k + 2] as u64) & 0xFFFFFFFF)
                    as u32),
                idxs[2].clone(),
            );
            b = u32_rotate_left(
                &(((b as u64 + md4_f(&c, &d, &a) as u64 + words[4 * k + 3] as u64) & 0xFFFFFFFF)
                    as u32),
                idxs[3].clone(),
            );
        }

        // Round 2
        idxs = vec![3usize, 5, 9, 13];
        for k in 0..4usize {
            a = u32_rotate_left(
                &(((a as u64 + md4_g(&b, &c, &d) as u64 + words[k] as u64 + 0x5A827999u64)
                    & 0xFFFFFFFF) as u32),
                idxs[0].clone(),
            );
            d = u32_rotate_left(
                &(((d as u64 + md4_g(&a, &b, &c) as u64 + words[k + 4] as u64 + 0x5A827999u64)
                    & 0xFFFFFFFF) as u32),
                idxs[1].clone(),
            );
            c = u32_rotate_left(
                &(((c as u64 + md4_g(&d, &a, &b) as u64 + words[k + 8] as u64 + 0x5A827999u64)
                    & 0xFFFFFFFF) as u32),
                idxs[2].clone(),
            );
            b = u32_rotate_left(
                &(((b as u64 + md4_g(&c, &d, &a) as u64 + words[k + 12] as u64 + 0x5A827999u64)
                    & 0xFFFFFFFF) as u32),
                idxs[3].clone(),
            );
        }

        // Round 3
        idxs = vec![3usize, 9, 11, 15];
        for k in vec![0usize, 2, 1, 3].iter() {
            a = u32_rotate_left(
                &(((a as u64 + md4_h(&b, &c, &d) as u64 + words[*k] as u64 + 0x6ED9EBA1u64)
                    & 0xFFFFFFFF) as u32),
                idxs[0].clone(),
            );
            d = u32_rotate_left(
                &(((d as u64 + md4_h(&a, &b, &c) as u64 + words[k + 8] as u64 + 0x6ED9EBA1u64)
                    & 0xFFFFFFFF) as u32),
                idxs[1].clone(),
            );
            c = u32_rotate_left(
                &(((c as u64 + md4_h(&d, &a, &b) as u64 + words[k + 4] as u64 + 0x6ED9EBA1u64)
                    & 0xFFFFFFFF) as u32),
                idxs[2].clone(),
            );
            b = u32_rotate_left(
                &(((b as u64 + md4_h(&c, &d, &a) as u64 + words[k + 12] as u64 + 0x6ED9EBA1u64)
                    & 0xFFFFFFFF) as u32),
                idxs[3].clone(),
            );
        }

        // Increment all four registers
        a = ((a as u64 + aa as u64) & 0xFFFFFFFF) as u32;
        b = ((b as u64 + bb as u64) & 0xFFFFFFFF) as u32;
        c = ((c as u64 + cc as u64) & 0xFFFFFFFF) as u32;
        d = ((d as u64 + dd as u64) & 0xFFFFFFFF) as u32;
    }

    // Produce final hash
    let mut a_vec: Vec<u8> = BitVec::new_from_num(32, &a)
        .to_bytearray()
        .into_iter()
        .rev()
        .collect();
    let b_vec: Vec<u8> = BitVec::new_from_num(32, &b)
        .to_bytearray()
        .into_iter()
        .rev()
        .collect();
    let c_vec: Vec<u8> = BitVec::new_from_num(32, &c)
        .to_bytearray()
        .into_iter()
        .rev()
        .collect();
    let d_vec: Vec<u8> = BitVec::new_from_num(32, &d)
        .to_bytearray()
        .into_iter()
        .rev()
        .collect();

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

#[cfg(test)]
mod tests {
    use super::*;

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
    fn test_md4() {
        let messages: Vec<Vec<u8>> = vec![
            b"a".to_vec(),
            b"abc".to_vec(),
            b"message digest".to_vec(),
            b"abcdefghijklmnopqrstuvwxyz".to_vec(),
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".to_vec(),
            b"12345678901234567890123456789012345678901234567890123456789012345678901234567890"
                .to_vec(),
        ];
        let expected: Vec<String> = vec![
            "bde52cb31de33e46245e05fbdbd6fb24".to_string(),
            "a448017aaf21d8525fc10ae87aa6729d".to_string(),
            "d9130a8164549fe818874806e1c7014b".to_string(),
            "d79e1c308aa5bbcdeea8ed63df412da9".to_string(),
            "043f8582f241db351ce627e153e7f0e4".to_string(),
            "e33b4ddc9c38f2199c3e7b164fcc0536".to_string(),
        ];
        for (input, output) in zip(messages.iter(), expected.iter()) {
            assert_eq!(md4(&BitVec::new_from_bytearray(input)), *output);
        }
    }
}
