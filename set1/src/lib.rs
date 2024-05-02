use std::collections::HashMap;
use std::iter::zip;

const HEXTABLE: &str = "0123456789abcdef";
const BASE64TABLE: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
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
    ('e', 12.7)
];

#[derive(Clone)]
pub struct SinglebyteXORDecryptionAnswer {
    pub plaintext: String,
    pub key: u8,
    pub score: f32
}

impl SinglebyteXORDecryptionAnswer {
    pub fn new(plaintext: String, key: u8, score: f32) -> SinglebyteXORDecryptionAnswer {
        SinglebyteXORDecryptionAnswer {
            plaintext: plaintext,
            key: key,
            score: score
        }
    }
}

fn hexsym2digit(letter: &char) -> i32 {
    if let Some(index) = HEXTABLE.find(*letter) {
        return index.try_into().unwrap();
    }
    panic!("Invalid hex symbol.");
}

fn base64sym2digit(letter: &char) -> i32 {
    if let Some(index) = BASE64TABLE.find(*letter) {
        return index.try_into().unwrap();
    }
    panic!("Invalid base64 character.");
}

fn digit2base64sym(digit: &i32) -> String {
    if *digit < 0 || *digit > 63 {
        panic!("Invalid base64 character.");
    }
    return String::from(BASE64TABLE
                            .chars()
                            .nth(*digit as usize)
                            .unwrap());
}

fn digit2hexsym(digit: &i32) -> String {
    if *digit < 0 || *digit > 15 {
        panic!("Invalid hex character.");
    }
    return String::from(HEXTABLE
                            .chars()
                            .nth(*digit as usize)
                            .unwrap());
}

pub fn hextobin(num_str: &String) -> String {
    num_str
        .chars()
        .map(|el| format!("{:04b}", hexsym2digit(&el)))
        .collect::<Vec<String>>()
        .join("")
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

pub fn bintobase64(num_str: &String) -> String {
    num_str
        .as_bytes()
        .chunks(6)
        .map(|el| digit2base64sym(
                        &i32::from_str_radix(
                            std::str::from_utf8(el)
                            .unwrap(), 2)
                        .unwrap()))
        .collect::<Vec<String>>()
        .join("")
}

pub fn bintohex(num_str: &String) -> String {
    num_str
        .as_bytes()
        .chunks(4)
        .map(|el| digit2hexsym(
                        &i32::from_str_radix(
                            std::str::from_utf8(el)
                            .unwrap(), 2)
                        .unwrap()))
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

pub fn edit_distance(ascii_str1: &String, ascii_str2: &String) -> u32 {
    if ascii_str1.len() != ascii_str2.len() {
        panic!("ASCII strings should be of the same length");
    }
    zip(asciitobin(&ascii_str1).chars(), 
        asciitobin(&ascii_str2).chars())
        .map(|(a, b)| (a != b) as u32)
        .sum()
}

pub fn hextobase64(hex: &String) -> String {
    bintobase64(&hextobin(hex))
}

pub fn base64tohex(base64: &String) -> String {
    bintohex(&base64tobin(base64))
}

pub fn hex_xor(buf1: &String, buf2: &String) -> String {
    if buf1.len() != buf2.len() {
        panic!("Buffers should be of the same length.");
    }
    let res: Vec<u8> = std::iter::zip(hextobin(buf1).chars(), hextobin(buf2).chars())
                            .map(|(a, b)| (a as u8 - 48) ^ (b as u8 - 48) + 48)
                            .collect();
    bintohex(&String::from_utf8(res).unwrap())
}

pub fn encrypt_singlebyte_xor(ascii_str: &String, key: u8) -> String {
    let bin_plaintext = asciitobin(&ascii_str);
    hex_xor(&bintohex(&bin_plaintext), 
                &bintohex(&format!("{:08b}", key)
                    .repeat(bin_plaintext.len() / 8)))
}

pub fn decrypt_singlebyte_xor(ciphertext: &String) -> Vec<SinglebyteXORDecryptionAnswer> {
    let mut scores = Vec::<SinglebyteXORDecryptionAnswer>::new();
    let num_bytes_in_ciphertext = (hextobin(&ciphertext)).len();
    let alphabet_ranks = HashMap::from(ALPHABET_RANKS);
    
    for elem in 0..=255u8 {
        let mut ans = SinglebyteXORDecryptionAnswer::new(
                    String::from(""), elem, 0.0f32);

        // Attempt decryption using candidate key
        let key = bintohex(&format!("{:08b}", elem)
                    .repeat(num_bytes_in_ciphertext / 8));
        let decrypted = bintoascii(&hextobin(&hex_xor(&key, ciphertext)));
        
        let mut freqs = HashMap::<char, i32>::new();
        let mut total_length: f32 = 0.0;
        
        // Count frequencies of lowercase alphabet characters
        // in the decrypted text
        for letter in decrypted.chars() {
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
    let bin_ciphertext: String = hextobin(ciphertext);
    let mut ciphertext_freqs = HashMap::<u8, f32>::new();
    let alphabet_ranks = HashMap::from(ALPHABET_RANKS);
    let mut scores = Vec::<SinglebyteXORDecryptionAnswer>::new();
    
    // Count frequencies of all possible bytes in the ciphertext
    for elem in 0..=255u8 {
        let count = ciphertext_freqs.entry(elem).or_insert(0.0f32);
        *count += bin_ciphertext
                    .matches((format!("{:08b}", elem)).as_str())
                    .collect::<Vec<_>>()
                    .len() as f32;
        *count /= bin_ciphertext.len() as f32 / 8.0;
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
        let key = bintohex(&format!("{:08b}", scores[count].key)
                                .repeat(bin_ciphertext.len() / 8));
        scores[count].plaintext = bintoascii(&hextobin(
                                    &hex_xor(&key, ciphertext)));
    }
    scores[0..10].to_vec()
}

pub fn encrypt_repeatingkey_xor(ascii_str: &String, ascii_key: &String) -> String {
    let bin_plaintext = asciitobin(&ascii_str);
    let bin_key = asciitobin(&ascii_key);
    let mut repeating_key = bin_key
                            .repeat(bin_plaintext.len() / bin_key.len());
    repeating_key.push_str(
        &bin_key[..(bin_plaintext.len() % bin_key.len())]);
    hex_xor(&bintohex(&bin_plaintext), &bintohex(&repeating_key))
}

pub fn decrypt_repeatingkey_xor(ciphertext: &String) -> String {
    let mut normalized_dist = Vec::<(u32, f32)>::new();
    for keysize in 2..=35usize {
        let normalized = edit_distance(
                        &ciphertext[..(keysize * 8)].to_string(), 
                        &ciphertext[(keysize * 8)..(2 * keysize * 8)].to_string()) 
                as f32 / keysize as f32;
        normalized_dist.push((keysize.try_into().unwrap(), normalized));
    }
    normalized_dist.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap());

    for count in 0..2 {
        let parts: Vec<String> = ciphertext
                          .as_bytes()
                          .chunks((normalized_dist[count].0 * 8)
                                      .try_into()
                                      .unwrap())
                          .map(|a| String::from_utf8(a.to_vec()).unwrap())
                          .collect();
        let mut to_decrypt = Vec::<String>::new();
        for size in 0..normalized_dist[count].0 {
            let start_idx: usize = (8 * size).try_into().unwrap();
            let end_idx: usize = (8 * (size + 1)).try_into().unwrap();
            let collected: String = parts
                        .iter()
                        .map(|a| match a.get(start_idx..end_idx) {
                            Some(b) => b,
                            None => "",
                        })
                        .collect::<Vec<_>>()
                        .join("");
            to_decrypt.push(collected);
        }
        let decrypted_keys: Vec<u8> = to_decrypt
                            .iter_mut()
                            .map(|a| decrypt_singlebyte_xor(&a))
                            .map(|b| b[0].key)
                            .collect();
        dbg!("{} {:?}", count, &decrypted_keys);
    }
    String::from("")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hextobin() {
        let hex = String::from("f1da6");
        assert_eq!(hextobin(&hex), "11110001110110100110");
    }

    #[test]
    fn test_base64tobin() {
        let base64 = String::from("hdje");
        assert_eq!(base64tobin(&base64), "100001011101100011011110");
    }

    #[test]
    fn test_bintohex() {
        let bin = String::from("11110001110110100110");
        assert_eq!(bintohex(&bin), "f1da6");
    }

    #[test]
    fn test_bintobase64() {
        let bin = String::from("100001011101100011011110");
        assert_eq!(bintobase64(&bin), "hdje");
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
    }

    #[test]
    fn test_bintoascii() {
        let bin_str = String::from("0100100100100000011001010110000101110100001000000110110101101111011101010111001101100101");
        assert_eq!(bintoascii(&bin_str), String::from("I eat mouse"));
    }

    #[test]
    fn test_asciitobin() {
        let ascii_str = String::from("I eat mouse");
        assert_eq!(asciitobin(&ascii_str), String::from("0100100100100000011001010110000101110100001000000110110101101111011101010111001101100101"));
    }

    #[test]
    fn test_edit_distance() {
        assert_eq!(edit_distance(&String::from("this is a test"),
                                &String::from("wokka wokka!!!")), 37u32);
    }

    #[test]
    fn test_encrypt_singlebyte_xor() {
        let plaintext = String::from("Cooking MC's like a pound of bacon");
        assert_eq!(encrypt_singlebyte_xor(&plaintext, 88u8), String::from("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"));
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
}
