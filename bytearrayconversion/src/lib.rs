/// bytearrayconversion library
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

const HEXTABLE: &str = "0123456789abcdef";
const BASE64TABLE: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn hexsym2digit(letter: &char) -> u8 {
    if let Some(index) = HEXTABLE.find(*letter) {
        return index.try_into().unwrap();
    }
    panic!("Invalid hex symbol.");
}

pub fn base64sym2digit(letter: &char) -> u8 {
    if let Some(index) = BASE64TABLE.find(*letter) {
        return index.try_into().unwrap();
    }
    panic!("Invalid base64 character {}.", *letter);
}

pub fn digit2base64sym(digit: &u8) -> String {
    if *digit > 63 {
        panic!("Invalid base64 character.");
    }
    return String::from(BASE64TABLE.chars().nth(*digit as usize).unwrap());
}

pub fn digit2hexsym(digit: &u8) -> String {
    if *digit > 15 {
        panic!("Invalid hex character.");
    }
    return String::from(HEXTABLE.chars().nth(*digit as usize).unwrap());
}

pub fn hextobin(num_str: &String) -> String {
    num_str
        .chars()
        .map(|el| format!("{:04b}", hexsym2digit(&el)))
        .collect::<Vec<String>>()
        .join("")
}

pub fn hextobytearray(num_str: &String) -> Vec<u8> {
    if num_str.len() % 2 != 0 {
        panic!("Hex string contains odd number of characters.");
    }
    let mut res = Vec::<String>::new();
    let mut num_str_iter = num_str.chars();
    for _ in (0..num_str.len()).step_by(2) {
        res.push(format!(
            "{}{}",
            num_str_iter.next().unwrap_or('\0'),
            num_str_iter.next().unwrap_or('\0')
        ));
    }
    res.iter()
        .map(|el| {
            hexsym2digit(&el.chars().nth(0).unwrap()) * 16
                + hexsym2digit(&el.chars().nth(1).unwrap())
        })
        .map(|el| el.try_into().unwrap())
        .collect::<Vec<u8>>()
}

pub fn base64tobin(num_str: &String) -> String {
    let bin_uncut = num_str
        .chars()
        .map(|el| format!("{:06b}", base64sym2digit(&el)))
        .collect::<Vec<String>>()
        .join("");
    bin_uncut
        .split_at(bin_uncut.len() - bin_uncut.len() % 8)
        .0
        .to_string()
}

pub fn base64tobytearray(num_str: &String) -> Vec<u8> {
    let mut res = Vec::<u8>::new();
    for chunk in num_str.as_bytes().chunks(4) {
        let block_value: u32 = chunk
            .iter()
            .enumerate()
            .map(|(i, a)| (base64sym2digit(&(*a as char)) as u32) * 2_u32.pow((6 * (3 - i)) as u32))
            .sum();

        for count in 0..(chunk.len() - 1) {
            let byte: u8 = ((block_value >> (2 - count) * 8) & 0xFF)
                .try_into()
                .unwrap();
            res.push(byte);
        }
    }
    res
}

pub fn bintobase64(num_str: &String) -> String {
    num_str
        .as_bytes()
        .chunks(6)
        .map(|el| {
            digit2base64sym(&u8::from_str_radix(std::str::from_utf8(el).unwrap(), 2).unwrap())
        })
        .collect::<Vec<String>>()
        .join("")
}

pub fn bytearraytobase64(bytearray: &Vec<u8>) -> String {
    let mut res = String::new();
    for chunk in bytearray.chunks(3) {
        let block_value: u32 = chunk
            .iter()
            .enumerate()
            .map(|(i, a)| (*a as u32) * 2_u32.pow((8 * (2 - i)) as u32))
            .sum();

        for count in 0..(chunk.len() + 1) {
            let index: u8 = (block_value >> ((3 - count) * 6) & 0x3F)
                .try_into()
                .unwrap();
            res.push_str(digit2base64sym(&index).as_str());
        }
    }
    res
}

pub fn bintohex(num_str: &String) -> String {
    num_str
        .as_bytes()
        .chunks(4)
        .map(|el| digit2hexsym(&u8::from_str_radix(std::str::from_utf8(el).unwrap(), 2).unwrap()))
        .collect::<Vec<String>>()
        .join("")
}

pub fn bytearraytohex(bytearray: &Vec<u8>) -> String {
    bytearray
        .iter()
        .map(|a| vec![(*a & 0xF0) >> 4, *a & 0x0F])
        .flatten()
        .map(|a| digit2hexsym(&a))
        .collect::<Vec<String>>()
        .join("")
}

pub fn bintoascii(bin_str: &String) -> String {
    bin_str
        .as_bytes()
        .chunks(8)
        .map(|el| std::str::from_utf8(el).unwrap())
        .map(|el| u8::from_str_radix(el, 2).unwrap())
        .map(|el| el as char)
        .collect::<String>()
}

pub fn asciitobin(ascii_str: &String) -> String {
    ascii_str
        .as_bytes()
        .iter()
        .map(|a| format!("{:08b}", a))
        .collect::<Vec<_>>()
        .join("")
}

pub fn hextobase64(hex: &String) -> String {
    bytearraytobase64(&hextobytearray(hex))
}

pub fn base64tohex(base64: &String) -> String {
    bytearraytohex(&base64tobytearray(base64))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hextobin() {
        let hex = String::from("0f1da6");
        assert_eq!(hextobin(&hex), "000011110001110110100110");
    }

    #[test]
    fn test_hextobytearray() {
        let hex = String::from("0f1da6");
        assert_eq!(hextobytearray(&hex), vec![15u8, 29u8, 166u8]);
    }

    #[test]
    fn test_base64tobin() {
        let base64 = String::from("hdje");
        assert_eq!(base64tobin(&base64), "100001011101100011011110");
    }

    #[test]
    fn test_base64tobytearray() {
        let base64 = String::from("hdjea2");
        assert_eq!(base64tobytearray(&base64), vec![133u8, 216u8, 222u8, 107u8]);
    }

    #[test]
    fn test_bintohex() {
        let bin = String::from("000011110001110110100110");
        assert_eq!(bintohex(&bin), "0f1da6");
    }

    #[test]
    fn test_bytearraytohex() {
        let bin = vec![15u8, 29u8, 166u8];
        assert_eq!(bytearraytohex(&bin), "0f1da6");
    }

    #[test]
    fn test_bintobase64() {
        let bin = String::from("100001011101100011011110");
        assert_eq!(bintobase64(&bin), "hdje");
    }

    #[test]
    fn test_bytearraytobase64() {
        let bin = vec![133u8, 216u8, 222u8, 107u8];
        assert_eq!(bytearraytobase64(&bin), "hdjeaw");
    }

    #[test]
    fn test_hextobase64() {
        let hex = String::from("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d");
        let base64 =
            String::from("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t");
        assert_eq!(hextobase64(&hex), base64);
    }

    #[test]
    fn test_base64tohex() {
        let hex = String::from("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d");
        let base64 =
            String::from("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t");
        assert_eq!(base64tohex(&base64), hex);
    }

    #[test]
    fn test_bintoascii() {
        let bin_str = String::from("0100100100100000011001010110000101110100001000000110110101101111011101010111001101100101");
        assert_eq!(bintoascii(&bin_str), String::from("I eat mouse"));
    }

    #[test]
    fn test_asciitobin() {
        let ascii_str = String::from("I eat mouse");
        assert_eq!(asciitobin(&ascii_str),
            String::from("0100100100100000011001010110000101110100001000000110110101101111011101010111001101100101"));
    }
}
