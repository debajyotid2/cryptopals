const HEXTABLE: &str = "0123456789abcdef";
const BASE64TABLE: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const ALPHABET_RANKS: &str = "ETAONRISHDLFCMUGYPWBVKJXZQ";

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

pub fn decrypt_singlebyteXOR(ciphertext: &String) -> String {
    let bin_ciphertext = hextobin(&ciphertext);
    for elem in 0..=255u8 {
        let res = hex_xor(&bintohex(&format!("{:08b}", elem)
                    .repeat(ciphertext.len())), ciphertext);
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
}
