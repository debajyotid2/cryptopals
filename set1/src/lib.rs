use std::collections::HashMap;

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

fn score_frequencies(ascii_str: &String) -> f32 {
    let alphabet_ranks = HashMap::from(ALPHABET_RANKS);
    let mut score: f32 = 0.0;
    let mut freqs = HashMap::<char, i32>::new();
    let mut total_length: f32 = 0.0;
    for letter in ascii_str.chars() {
        if !(letter.is_ascii_alphabetic() && letter.is_ascii_lowercase()) { continue; }
        let count = freqs.entry(letter).or_insert(0i32);
        *count += 1;
        total_length += 1.0;
    }
    if freqs.is_empty() { return std::f32::INFINITY; }
    let mut sorted_freqs: Vec<(&char, &i32)> = freqs
                                        .iter()
                                        .collect();
    sorted_freqs.sort_by(|a, b| b.1.cmp(&a.1));
    for (letter, count) in sorted_freqs.iter() {
        let freq = **count as f32 / total_length;
        score += (alphabet_ranks[&letter] / 100.0 - freq) *
                 (alphabet_ranks[&letter] / 100.0 - freq);
    }
    score
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

pub fn decrypt_singlebyte_xor(ciphertext: &String) -> Vec<String> {
    let mut scores = Vec::<(String, f32)>::new();
    let num_bytes_in_ciphertext = (hextobin(&ciphertext)).len();
    for elem in 0..=255u8 {
        let key = bintohex(&format!("{:08b}", elem)
                    .repeat(num_bytes_in_ciphertext / 8));
        let decrypted = bintoascii(&hextobin(&hex_xor(&key, ciphertext)));
        let score = score_frequencies(&decrypted);
        scores.push((decrypted, score));
    }
    scores.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
    scores.reverse();

    let res = scores
                .iter()
                .map(|(a, _)| a.clone())
                .collect::<Vec<String>>();
    res[0..5].to_vec()
}

pub fn decrypt_singlebyte_xor_faster(ciphertext: &String) -> Vec<String> {
    let bin_ciphertext: String = hextobin(ciphertext);
    let mut ciphertext_freqs = HashMap::<u8, f32>::new();
    let alphabet_ranks = HashMap::from(ALPHABET_RANKS);
    let mut scores = Vec::<(u8, f32)>::new();
    
    for elem in 0..=255u8 {
        let count = ciphertext_freqs.entry(elem).or_insert(0.0f32);
        *count += bin_ciphertext
                    .matches((format!("{:08b}", elem)).as_str())
                    .collect::<Vec<_>>()
                    .len() as f32;
        *count /= bin_ciphertext.len() as f32 / 8.0;
    }

    dbg!("{:?}", &ciphertext_freqs);
    
    for elem in 0..=255u8 {
        let mut score: f32 = 0.0;
        for (letter, freq) in alphabet_ranks.iter() {
            score += (freq / 100.0 - ciphertext_freqs[&(*letter as u8 ^ elem)]).powi(2);
        }
        scores.push((elem, score));
    }
    scores.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap());
    scores.reverse();

    let mut res = Vec::<String>::new();
    for count in 0..5 {
        res.push(bintoascii(
                    &hextobin(
                        &hex_xor(ciphertext, 
                            &bintohex(&format!("{:08b}", scores[count].0)
                                        .repeat(bin_ciphertext.len() / 8))
                    )
                )
            )
        );
        dbg!("{}: {}", scores[count].0, scores[count].1);
    }
    res
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
}
