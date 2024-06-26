use std::collections::HashMap;
use std::iter::zip;
use aes::Aes128;
use aes::cipher::{
    BlockDecrypt, KeyInit,
    generic_array::GenericArray,
};

const HEXTABLE: &str = "0123456789abcdef";
const BASE64TABLE: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const ALPHABET_RANKS: [(char, f32); 26] = [
    ('z', 0.074), ('q', 0.095), ('x', 0.15), ('j', 0.15), ('k', 0.77), ('v', 0.98), ('b', 1.5),
    ('p', 1.9), ('y', 2.0), ('g', 2.0), ('f', 2.2), ('w', 2.4), ('m', 2.4), ('c', 2.8), ('u', 2.8),
    ('l', 4.0), ('d', 4.3), ('r', 6.0), ('h', 6.1), ('s', 6.3), ('n', 6.7), ('i', 7.0), ('o', 7.5),
    ('a', 8.2), ('t', 9.1), ('e', 12.7)
];

#[derive(Clone)]
pub struct SinglebyteXORDecryptionAnswer {
    pub plaintext: Option<String>,
    pub key: u8,
    pub score: f32
}

impl SinglebyteXORDecryptionAnswer {
    pub fn new(plaintext: String, key: u8, score: f32) -> SinglebyteXORDecryptionAnswer {
        SinglebyteXORDecryptionAnswer {
            plaintext: Some(plaintext),
            key: key,
            score: score
        }
    }
}

// Custom error type
#[derive(Debug)]
pub enum Err {
    BufferLengthError(usize, usize),
}

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
    return String::from(BASE64TABLE
                            .chars()
                            .nth(*digit as usize)
                            .unwrap());
}

pub fn digit2hexsym(digit: &u8) -> String {
    if *digit > 15 {
        panic!("Invalid hex character.");
    }
    return String::from(HEXTABLE
                            .chars()
                            .nth(*digit as usize)
                            .unwrap());
}

fn hamming_weight(mut val: u8) -> u32 {
    let mut weight = 0u32;
    while val != 0u8 {
        weight += (val & 1) as u32;
        val >>= 1;
    }
    weight
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
        res.push(format!("{}{}", 
                num_str_iter.next().unwrap_or('\0'), 
                num_str_iter.next().unwrap_or('\0')));
    }
    res
        .iter()
        .map(|el| hexsym2digit(&el.chars().nth(0).unwrap()) * 16 +
                  hexsym2digit(&el.chars().nth(1).unwrap()))
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
                            .map(|(i, a)| (
                                base64sym2digit(&(*a as char)) as u32) *
                                2_u32.pow((6 * (3 - i)) as u32))
                            .sum();

        for count in 0..(chunk.len() - 1) {
            let byte: u8 = (((block_value >> (2 - count) * 8)) & 0xFF)
                                .try_into().unwrap();
            res.push(byte);
        }
    }
    res
}

pub fn bintobase64(num_str: &String) -> String {
    num_str
        .as_bytes()
        .chunks(6)
        .map(|el| digit2base64sym(
                        &u8::from_str_radix(
                            std::str::from_utf8(el)
                            .unwrap(), 2)
                        .unwrap()))
        .collect::<Vec<String>>()
        .join("")
}

pub fn bytearraytobase64(bytearray: &Vec<u8>) -> String {
    let mut res = String::new();
    for chunk in bytearray.chunks(3) {
        let block_value: u32 = chunk
                            .iter()
                            .enumerate()
                            .map(|(i, a)| 
                                (*a as u32) * 2_u32.pow((8 * (2 - i)) as u32)
                             )
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
        .map(|el| digit2hexsym(
                        &u8::from_str_radix(
                            std::str::from_utf8(el)
                            .unwrap(), 2)
                        .unwrap()))
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

pub fn edit_distance(ascii_str1: &String, ascii_str2: &String) -> Result<u32, Err> {
    if ascii_str1.len() != ascii_str2.len() {
        Err(Err::BufferLengthError(ascii_str1.len(), ascii_str2.len()))
    } else {
        Ok(zip(asciitobin(&ascii_str1).chars(), 
            asciitobin(&ascii_str2).chars())
            .map(|(a, b)| (a != b) as u32)
            .sum())
    }
}

pub fn edit_distance_2(buf1: &Vec<u8>, buf2: &Vec<u8>) -> Result<u32, Err> {
    if buf1.len() != buf2.len() {
        Err(Err::BufferLengthError(buf1.len(), buf2.len()))
    } else {
        Ok(zip(buf1.iter(), 
            buf2.iter())
            .map(|(a, b)| a ^ b)
            .map(hamming_weight)
            .sum::<u32>())
    }
}

pub fn hextobase64(hex: &String) -> String {
    bytearraytobase64(&hextobytearray(hex))
}

pub fn base64tohex(base64: &String) -> String {
    bytearraytohex(&base64tobytearray(base64))
}

pub fn hex_xor(buf1: &String, buf2: &String) -> String {
    let bin_buf1: Vec<u8> = hextobytearray(buf1);
    let bin_buf2: Vec<u8> = hextobytearray(buf2);
    if bin_buf1.len() != bin_buf2.len() {
        panic!("Buffers buf1 and buf2 should be of the same length, but have lengths {} and {}.",
            bin_buf1.len(), bin_buf2.len());
    }

    let res: Vec<u8> = std::iter::zip(bin_buf1.iter(), bin_buf2.iter())
                            .map(|(a, b)| a ^ b)
                            .collect();
    bytearraytohex(&res)
}

pub fn encrypt_singlebyte_xor(ascii_str: &String, key: u8) -> String {
    let bytes_plaintext = ascii_str.as_bytes().to_vec();
    hex_xor(&bytearraytohex(&bytes_plaintext), 
            &bytearraytohex(&vec![key].repeat(bytes_plaintext.len())))
}

pub fn decrypt_singlebyte_xor(ciphertext: &String) -> Vec<SinglebyteXORDecryptionAnswer> {
    let mut scores = Vec::<SinglebyteXORDecryptionAnswer>::new();
    let alphabet_ranks = HashMap::from(ALPHABET_RANKS);
    let num_bytes_in_ciphertext = (hextobytearray(&ciphertext)).len();
    
    for elem in 0..=255u8 {
        let mut ans = SinglebyteXORDecryptionAnswer::new(
                    String::from(""), elem, 0.0f32);

        // Attempt decryption using key
        let key = bytearraytohex(&vec![elem]
                            .repeat(num_bytes_in_ciphertext));
        let bytes = hextobytearray(&hex_xor(&key, ciphertext));
        match String::from_utf8(bytes) {
            Ok(string) => {
                ans.plaintext = Some(string);
            },
            Err(_) => {
                ans.plaintext = None;
                ans.score = std::f32::INFINITY;
                scores.push(ans);
                continue;
            }
        };

        let mut freqs = HashMap::<char, i32>::new();
        let mut total_length: f32 = 0.0;
        
        // Count frequencies of lowercase alphabet characters
        // in the decrypted text
        for letter in ans.plaintext
                        .as_ref()
                        .unwrap()
                        .chars() {
            if !(letter.is_ascii_alphabetic() &&
                 letter.is_ascii_lowercase()) {
                continue;
            }
            let count = freqs.entry(letter).or_insert(0i32);
            *count += 1;
            total_length += 1.0;
        }

        if freqs.is_empty() { 
            ans.score = std::f32::INFINITY;
            scores.push(ans);
            continue;
        }

        // Score the decrypted string according to closeness to
        // expected frequencies of lowercase letters
        let mut sorted_freqs: Vec<(&char, &i32)> = freqs
                                            .iter()
                                            .collect();
        sorted_freqs.sort_by(|a, b| b.1.cmp(&a.1));
        for (letter, count) in sorted_freqs.iter() {
            let freq = **count as f32 / total_length;
            ans.score += (alphabet_ranks[&letter] / 100.0 - freq).abs();
        }

        scores.push(ans);
    }

    // Sort scores
    scores.sort_by(|a, b| a.score.partial_cmp(&b.score).unwrap());

    // Return results from top 10 lowest scoring keys
    scores[0..10].to_vec()
}

pub fn decrypt_singlebyte_xor_faster(ciphertext: &String) -> Vec<SinglebyteXORDecryptionAnswer> {
    let bytes_ciphertext: Vec<u8> = hextobytearray(ciphertext);
    let mut ciphertext_freqs = HashMap::<u8, f32>::new();
    let alphabet_ranks = HashMap::from(ALPHABET_RANKS);
    let mut scores = Vec::<SinglebyteXORDecryptionAnswer>::new();
    
    // Count frequencies of all possible bytes in the ciphertext
    for elem in 0..=255u8 {
        let count = ciphertext_freqs.entry(elem).or_insert(0.0f32);
        *count += bytes_ciphertext
                    .iter()
                    .filter(|x| **x == elem)
                    .count() as f32;
        *count /= bytes_ciphertext.len() as f32;
    }
    
    // Since the algorithm is a single character Caesar cipher,
    // the frequency counts are just a permutation of the frequency
    // counts of the actual characters. 
    // For each byte, score it based on the frequencies counted
    // from the ciphertext relative to the expected frequencies.
    for elem in 0..=255u8 {
        let mut ans = SinglebyteXORDecryptionAnswer::new(
                String::from(""), elem, 0.0f32
            );
        for (letter, freq) in alphabet_ranks.iter() {
            ans.score += (freq / 100.0 -
                ciphertext_freqs[&(*letter as u8 ^ elem)]).abs();
        }
        scores.push(ans);
    }
    
    // Sort the scores
    scores.sort_by(|a, b| a.score.partial_cmp(&b.score).unwrap());
    
    // Decrypt for top 10 lowest scoring keys and return the plaintexts
    for count in 0..10 {
        let key = bytearraytohex(&vec![scores[count].key]
                                    .repeat(bytes_ciphertext.len()));
        let bytes = hextobytearray(&hex_xor(&key, ciphertext));
        scores[count].plaintext = match String::from_utf8(bytes) {
            Ok(decrypted) => Some(decrypted),
            Err(_) => None
        };
    }
    scores[0..10].to_vec()
}

pub fn encrypt_repeatingkey_xor(ascii_str: &String, ascii_key: &String) -> String {
    let bytes_plaintext = ascii_str.as_bytes().to_vec();
    let bytes_key = ascii_key.as_bytes().to_vec();
    let mut repeating_key = bytes_key
                            .repeat(bytes_plaintext.len() / bytes_key.len());
    repeating_key.append(
        &mut bytes_key[..(bytes_plaintext.len() % bytes_key.len())].to_vec());
    hex_xor(&bytearraytohex(&bytes_plaintext), &bytearraytohex(&repeating_key))
}

pub fn decrypt_repeatingkey_xor(ciphertext: &Vec<u8>) -> Vec<(String, f32)> {
    // Try to find the length of the repeating key from the 
    // Hamming distance between blocks of keysize bytes
    let mut normalized_dist = Vec::<(usize, f32)>::new();
    for keysize in 2..=40usize {
        let mut normalized;
        let slices: Vec<Vec<u8>> = ciphertext
                                        .chunks(keysize)
                                        .map(|a| a.to_vec())
                                        .collect();
        if slices.len() >= 4 {
            let distances: Vec<u32> = vec![
                          edit_distance_2(&slices[0], &slices[1]),
                          edit_distance_2(&slices[1], &slices[2]),
                          edit_distance_2(&slices[2], &slices[3]),
                          edit_distance_2(&slices[0], &slices[2]),
                          edit_distance_2(&slices[1], &slices[3]),
                          edit_distance_2(&slices[0], &slices[3])]
                              .iter()
                              .filter(|a| a.as_ref().is_ok())
                              .map(|a| *a.as_ref().unwrap())
                              .collect();
            normalized = distances.iter().sum::<u32>() as f32 / distances.len() as f32;
            normalized /= keysize as f32;
        } else {
            if let Ok(sth) = edit_distance_2(&slices[0], &slices[1]) { 
               normalized = sth as f32 / keysize as f32;
            } else { continue; }
        }
        normalized_dist.push((keysize, normalized));
    }
    normalized_dist.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap());

    // Take keysizes with lowest five edit distances
    let mut result = Vec::<(String, f32)>::new();
    for count in 0..5 {
        // For each key size, gather the bytes from the ciphertext
        // in intervals of the key size. Then decrypt the gathered
        // strings as if they are single byte XOR encrypted.
        let mut to_decrypt = Vec::<String>::new();
        for idx in 1..=normalized_dist[count].0 {
            let collected: Vec<u8> = ciphertext
                        .iter()
                        .skip(idx - 1)
                        .step_by(normalized_dist[count].0)
                        .copied()
                        .collect();
            to_decrypt.push(bytearraytohex(&collected));
        }
        let decrypted_keys: Vec<(u8, f32)> = to_decrypt
                            .iter()
                            .map(|a| decrypt_singlebyte_xor_faster(&a))
                            .map(|b| (b[0].key, b[0].score))
                            .collect();
        result.push((
            String::from_utf8(
                decrypted_keys.iter().map(|(a, _)| *a).collect::<Vec<u8>>()
            ).unwrap(),
            decrypted_keys.iter().map(|(_, b)| *b).sum::<f32>() / normalized_dist[count].0 as f32
        ));
    }
    result.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap());
    result[0..5].to_vec()
}

pub fn decrypt_aes_ecb(ciphertext: &Vec<u8>, key: &Vec<u8>) -> Vec<u8> {
    let key_arr: [u8; 16] = key.clone().try_into().unwrap();
    let key_val = GenericArray::from(key_arr);

    let cipher = Aes128::new(&key_val);

    let ciphertext_blocks: Vec<[u8; 16]> = ciphertext
                    .chunks(16)
                    .map(|chunk| {
                        let arr: [u8; 16] = chunk
                                .try_into()
                                .unwrap_or({
                            let mut chunk_copy = chunk.to_vec();
                            chunk_copy    
                                .extend_from_slice(
                                    &vec![0u8].repeat(16 - chunk.len()));
                            let val: [u8; 16] = chunk_copy
                                            .try_into().unwrap();
                            val
                        });
                        arr
                    })
                    .collect();
    ciphertext_blocks
            .iter()
            .map(|block| {
                let mut decrypted = GenericArray::from(*block);
                cipher.decrypt_block(&mut decrypted);
                decrypted.to_vec()
            })
            .flatten()
            .collect()
}

pub fn detect_aes_ecb_encryption(hex_ciphertext: &String) -> usize {
    let ciphertext: Vec<Vec<[u8; 16]>> = hex_ciphertext
                    .lines()
                    .map(|line| hextobytearray(&line.to_string()))
                    .map(|vec| {
                         vec.chunks(16)
                            .map(|chunk| {
                                let arr: [u8; 16] = chunk.try_into().unwrap();
                                arr
                            })
                            .collect()
                        })
                    .collect();
    for (lineno, vec) in ciphertext.iter().enumerate() {
        for arr in vec {
            let count = vec.iter().filter(|el| **el == *arr).count();
            if count < 2 {
                continue;
            } else {
                return lineno + 1;
            }
        }
    }
    0
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
        assert_eq!(base64tobytearray(&base64), 
                   vec![133u8, 216u8, 222u8, 107u8]);
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
        let base64 = String::from("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t");
        assert_eq!(hextobase64(&hex), base64);
    }

    #[test]
    fn test_base64tohex() {
        let hex = String::from("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d");
        let base64 = String::from("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t");
        assert_eq!(base64tohex(&base64), hex);
    }

    #[test]
    fn test_hex_xor() {
        let hex1 = String::from("1c0111001f010100061a024b53535009181c");
        let hex2 = String::from("686974207468652062756c6c277320657965");
        assert_eq!(hex_xor(&hex1, &hex2), 
            String::from("746865206b696420646f6e277420706c6179"));
        assert_eq!(hex_xor(&hex2, &hex1), 
            String::from("746865206b696420646f6e277420706c6179"));
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

    #[test]
    fn test_edit_distance() {
        let str1 = String::from("this is a test");
        let str2 = String::from("wokka wokka!!!");
        assert_eq!(edit_distance(&str1, &str2).ok().unwrap(), 37u32);
        assert_eq!(edit_distance(&str2, &str1).ok().unwrap(), 37u32);
    }

    #[test]
    fn test_edit_distance_2() {
        let buf1: Vec<u8> = String::from("this is a test")
                                .as_bytes().to_vec();
        let buf2: Vec<u8> = String::from("wokka wokka!!!")
                                .as_bytes().to_vec();
        assert_eq!(edit_distance_2(&buf1, &buf2).ok().unwrap(), 37u32);
        assert_eq!(edit_distance_2(&buf2, &buf1).ok().unwrap(), 37u32);
    }

    #[test]
    fn test_encrypt_singlebyte_xor() {
        let plaintext = String::from("Cooking MC's like a pound of bacon");
        assert_eq!(encrypt_singlebyte_xor(&plaintext, 88u8), 
            String::from("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"));
    }

    #[test]
    fn test_decrypt_singlebyte_xor() {
        let ciphertext = String::from("514542204e52465a4820594f4c544b20434c552047524a4d50204c53424f20514542204958575620414c440a");
        assert_eq!((decrypt_singlebyte_xor(&ciphertext)).len(), 10);
    }

    #[test]
    fn test_decrypt_singlebyte_xor_faster() {
        let ciphertext = String::from("514542204e52465a4820594f4c544b20434c552047524a4d50204c53424f20514542204958575620414c440a");
        assert_eq!((decrypt_singlebyte_xor_faster(&ciphertext)).len(), 10);
    }
    
    #[test]
    fn test_encrypt_repeatingkey_xor() {
        let plaintext = String::from("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal");
        let key = String::from("ICE");
        assert_eq!(encrypt_repeatingkey_xor(&plaintext, &key), 
                    String::from("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"));
    }

    #[test]
    fn test_decrypt_repeatingkey_xor() {
        let ciphertext: Vec<u8> = hextobytearray(&String::from("514542204e52465a4820594f4c544b20434c552047524a4d50204c53424f20514542204958575620414c440a"));
        let matches = decrypt_repeatingkey_xor(&ciphertext); 
        assert_eq!(matches.len(), 5);
    }

    #[test]
    fn test_decrypt_aes_ecb() {
        let ciphertext: Vec<u8> = vec![9, 18, 48, 170, 222, 62, 179, 48, 219, 170, 67, 88, 248, 141, 42, 108];
        let key: Vec<u8> = String::from("YELLOW SUBMARINE").as_bytes().to_vec();
        let plaintext: Vec<u8> = vec![73, 39, 109, 32, 98, 97, 99, 107, 32, 97, 110, 100, 32, 73, 39, 109];
        assert_eq!(&decrypt_aes_ecb(&ciphertext, &key), &plaintext);
    }
}
