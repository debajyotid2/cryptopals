use bytearrayconversion::{asciitobin, bytearraytohex, hextobytearray};
/// helper functions for xorcipher library
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
use std::iter::zip;

// Custom error type
#[derive(Debug)]
pub enum Err {
    BufferLengthError(usize, usize),
}

fn hamming_weight(mut val: u8) -> u32 {
    let mut weight = 0u32;
    while val != 0u8 {
        weight += (val & 1) as u32;
        val >>= 1;
    }
    weight
}

pub fn edit_distance(ascii_str1: &String, ascii_str2: &String) -> Result<u32, Err> {
    if ascii_str1.len() != ascii_str2.len() {
        Err(Err::BufferLengthError(ascii_str1.len(), ascii_str2.len()))
    } else {
        Ok(zip(
            asciitobin(&ascii_str1).chars(),
            asciitobin(&ascii_str2).chars(),
        )
        .map(|(a, b)| (a != b) as u32)
        .sum())
    }
}

pub fn edit_distance_2(buf1: &Vec<u8>, buf2: &Vec<u8>) -> Result<u32, Err> {
    if buf1.len() != buf2.len() {
        Err(Err::BufferLengthError(buf1.len(), buf2.len()))
    } else {
        Ok(zip(buf1.iter(), buf2.iter())
            .map(|(a, b)| a ^ b)
            .map(hamming_weight)
            .sum::<u32>())
    }
}

pub fn hex_xor(buf1: &String, buf2: &String) -> String {
    let bin_buf1: Vec<u8> = hextobytearray(buf1);
    let bin_buf2: Vec<u8> = hextobytearray(buf2);
    if bin_buf1.len() != bin_buf2.len() {
        panic!(
            "Buffers buf1 and buf2 should be of the same length, but have lengths {} and {}.",
            bin_buf1.len(),
            bin_buf2.len()
        );
    }

    let res: Vec<u8> = std::iter::zip(bin_buf1.iter(), bin_buf2.iter())
        .map(|(a, b)| a ^ b)
        .collect();
    bytearraytohex(&res)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_hex_xor() {
        let hex1 = String::from("1c0111001f010100061a024b53535009181c");
        let hex2 = String::from("686974207468652062756c6c277320657965");
        assert_eq!(
            hex_xor(&hex1, &hex2),
            String::from("746865206b696420646f6e277420706c6179")
        );
        assert_eq!(
            hex_xor(&hex2, &hex1),
            String::from("746865206b696420646f6e277420706c6179")
        );
    }

    #[test]
    fn test_edit_distance() {
        let str1 = String::from("this is a test");
        let str2 = String::from("wokka wokka!!!");
        assert_eq!(edit_distance(&str1, &str2).ok().unwrap(), 37u32);
        assert_eq!(edit_distance(&str2, &str1).ok().unwrap(), 37u32);
    }

    #[test]
    fn test_edit_distance_2() {
        let buf1: Vec<u8> = String::from("this is a test").as_bytes().to_vec();
        let buf2: Vec<u8> = String::from("wokka wokka!!!").as_bytes().to_vec();
        assert_eq!(edit_distance_2(&buf1, &buf2).ok().unwrap(), 37u32);
        assert_eq!(edit_distance_2(&buf2, &buf1).ok().unwrap(), 37u32);
    }
}
