use bytearrayconversion::{bytearraytohex, hextobytearray};
/// xorcipher library
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
use std::collections::HashMap;

mod helpers;

pub use helpers::*;

const ALPHABET_RANKS: [(char, f32); 26] = [
    ('z', 0.074),
    ('q', 0.095),
    ('x', 0.15),
    ('j', 0.15),
    ('k', 0.77),
    ('v', 0.98),
    ('b', 1.5),
    ('p', 1.9),
    ('y', 2.0),
    ('g', 2.0),
    ('f', 2.2),
    ('w', 2.4),
    ('m', 2.4),
    ('c', 2.8),
    ('u', 2.8),
    ('l', 4.0),
    ('d', 4.3),
    ('r', 6.0),
    ('h', 6.1),
    ('s', 6.3),
    ('n', 6.7),
    ('i', 7.0),
    ('o', 7.5),
    ('a', 8.2),
    ('t', 9.1),
    ('e', 12.7),
];

#[derive(Clone)]
pub struct SinglebyteXORDecryptionAnswer {
    pub plaintext: Option<String>,
    pub key: u8,
    pub score: f32,
}

impl SinglebyteXORDecryptionAnswer {
    pub fn new(plaintext: String, key: u8, score: f32) -> SinglebyteXORDecryptionAnswer {
        SinglebyteXORDecryptionAnswer {
            plaintext: Some(plaintext),
            key: key,
            score: score,
        }
    }
}

pub fn encrypt_singlebyte_xor(ascii_str: &String, key: u8) -> String {
    let bytes_plaintext = ascii_str.as_bytes().to_vec();
    hex_xor(
        &bytearraytohex(&bytes_plaintext),
        &bytearraytohex(&vec![key].repeat(bytes_plaintext.len())),
    )
}

pub fn decrypt_singlebyte_xor(ciphertext: &String) -> Vec<SinglebyteXORDecryptionAnswer> {
    let mut scores = Vec::<SinglebyteXORDecryptionAnswer>::new();
    let alphabet_ranks = HashMap::from(ALPHABET_RANKS);
    let num_bytes_in_ciphertext = (hextobytearray(&ciphertext)).len();

    for elem in 0..=255u8 {
        let mut ans = SinglebyteXORDecryptionAnswer::new(String::from(""), elem, 0.0f32);

        // Attempt decryption using key
        let key = bytearraytohex(&vec![elem].repeat(num_bytes_in_ciphertext));
        let bytes = hextobytearray(&hex_xor(&key, ciphertext));
        match String::from_utf8(bytes) {
            Ok(string) => {
                ans.plaintext = Some(string);
            }
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
        for letter in ans.plaintext.as_ref().unwrap().chars() {
            if !(letter.is_ascii_alphabetic() && letter.is_ascii_lowercase()) {
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
        let mut sorted_freqs: Vec<(&char, &i32)> = freqs.iter().collect();
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
        *count += bytes_ciphertext.iter().filter(|x| **x == elem).count() as f32;
        *count /= bytes_ciphertext.len() as f32;
    }

    // Since the algorithm is a single character Caesar cipher,
    // the frequency counts are just a permutation of the frequency
    // counts of the actual characters.
    // For each byte, score it based on the frequencies counted
    // from the ciphertext relative to the expected frequencies.
    for elem in 0..=255u8 {
        let mut ans = SinglebyteXORDecryptionAnswer::new(String::from(""), elem, 0.0f32);
        for (letter, freq) in alphabet_ranks.iter() {
            ans.score += (freq / 100.0 - ciphertext_freqs[&(*letter as u8 ^ elem)]).abs();
        }
        scores.push(ans);
    }

    // Sort the scores
    scores.sort_by(|a, b| a.score.partial_cmp(&b.score).unwrap());

    // Decrypt for top 10 lowest scoring keys and return the plaintexts
    for count in 0..10 {
        let key = bytearraytohex(&vec![scores[count].key].repeat(bytes_ciphertext.len()));
        let bytes = hextobytearray(&hex_xor(&key, ciphertext));
        scores[count].plaintext = match String::from_utf8(bytes) {
            Ok(decrypted) => Some(decrypted),
            Err(_) => None,
        };
    }
    scores[0..10].to_vec()
}

pub fn encrypt_repeatingkey_xor(ascii_str: &String, ascii_key: &String) -> String {
    let bytes_plaintext = ascii_str.as_bytes().to_vec();
    let bytes_key = ascii_key.as_bytes().to_vec();
    let mut repeating_key = bytes_key.repeat(bytes_plaintext.len() / bytes_key.len());
    repeating_key.append(&mut bytes_key[..(bytes_plaintext.len() % bytes_key.len())].to_vec());
    hex_xor(
        &bytearraytohex(&bytes_plaintext),
        &bytearraytohex(&repeating_key),
    )
}

pub fn decrypt_repeatingkey_xor(ciphertext: &Vec<u8>) -> Vec<(String, f32)> {
    // Try to find the length of the repeating key from the
    // Hamming distance between blocks of keysize bytes
    let mut normalized_dist = Vec::<(usize, f32)>::new();
    for keysize in 2..=40usize {
        let mut normalized;
        let slices: Vec<Vec<u8>> = ciphertext.chunks(keysize).map(|a| a.to_vec()).collect();
        if slices.len() >= 4 {
            let distances: Vec<u32> = vec![
                edit_distance_2(&slices[0], &slices[1]),
                edit_distance_2(&slices[1], &slices[2]),
                edit_distance_2(&slices[2], &slices[3]),
                edit_distance_2(&slices[0], &slices[2]),
                edit_distance_2(&slices[1], &slices[3]),
                edit_distance_2(&slices[0], &slices[3]),
            ]
            .iter()
            .filter(|a| a.as_ref().is_ok())
            .map(|a| *a.as_ref().unwrap())
            .collect();
            normalized = distances.iter().sum::<u32>() as f32 / distances.len() as f32;
            normalized /= keysize as f32;
        } else {
            if let Ok(sth) = edit_distance_2(&slices[0], &slices[1]) {
                normalized = sth as f32 / keysize as f32;
            } else {
                continue;
            }
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
            String::from_utf8(decrypted_keys.iter().map(|(a, _)| *a).collect::<Vec<u8>>()).unwrap(),
            decrypted_keys.iter().map(|(_, b)| *b).sum::<f32>() / normalized_dist[count].0 as f32,
        ));
    }
    result.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap());
    result[0..5].to_vec()
}

pub fn decrypt_known_keysize_repeatingkey_xor(ciphertext: &Vec<u8>, keysize: &usize) -> Vec<u8> {
    let mut to_decrypt = Vec::<String>::new();
    for idx in 1..=(*keysize) {
        let collected: Vec<u8> = ciphertext
            .iter()
            .skip(idx - 1)
            .step_by(16)
            .copied()
            .collect();
        to_decrypt.push(bytearraytohex(&collected));
    }
    let decrypted_keys: Vec<(u8, f32)> = to_decrypt
        .iter()
        .map(|a| decrypt_singlebyte_xor(&a))
        .map(|b| (b[0].key, b[0].score))
        .collect();
    decrypted_keys.iter().map(|(a, _)| *a).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_singlebyte_xor() {
        let plaintext = String::from("Cooking MC's like a pound of bacon");
        assert_eq!(
            encrypt_singlebyte_xor(&plaintext, 88u8),
            String::from("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
        );
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
        let plaintext = String::from(
            "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal",
        );
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
}
