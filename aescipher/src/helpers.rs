use bytearrayconversion::{bytearraytohex, digit2hexsym};
/// Helper functions for aescipher
//
//                    GNU AFFERO GENERAL PUBLIC LICENSE
//                    Version 3, 19 November 2007

// Copyright (C) 2024 Debajyoti Debnath

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.

// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
//
use rand::prelude::*;

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

pub fn u8tohex(val: &u8) -> String {
    let lower_bits = digit2hexsym(&(val & 0x0F));
    let higher_bits = digit2hexsym(&(val >> 4 & 0x0F));
    format!("{}{}", &higher_bits, &lower_bits)
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
    res.extend_from_slice(
        &vec![(block_length - block.len()) as u8].repeat(block_length - block.len()),
    );
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pad_pkcs7() {
        let block: Vec<u8> = b"Pigs are fly".to_vec();
        assert_eq!((pad_pkcs7(&block, 16)).unwrap().len(), 16);
        assert_eq!(
            (pad_pkcs7(&block, 16)).unwrap(),
            b"Pigs are fly\x04\x04\x04\x04"
        );
    }

    #[test]
    fn test_generate_random_bytevec() {
        assert_eq!((generate_random_bytevec(16usize)).len(), 16usize);
    }

    #[test]
    fn test_strip_pkcs7_padding() {
        let bytes: Vec<u8> = b"Bytes are fun!\xae\xae\xae\xae\xae".to_vec();
        assert_eq!(
            strip_pkcs7_padding(&bytes).unwrap(),
            b"Bytes are fun!".to_vec()
        );

        let bytes_no_padding: Vec<u8> = b"ICE ICE BABY\x01\x02\x03\x04".to_vec();
        assert_eq!(
            strip_pkcs7_padding(&bytes_no_padding),
            Err(Error::NoPadBytesFound)
        );
    }
}
