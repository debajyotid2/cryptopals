const HEXDIGITS: &str = "0123456789";
const HEXCHARS: &str = "abcdef";

fn hexsym2digit(letter: &char) -> i32 {
    if let Some(index) = HEXDIGITS.find(*letter) {
        return index.try_into().unwrap();
    } else if let Some(index) = HEXCHARS.find(*letter) {
        return (10 + index).try_into().unwrap();
    } else {
        panic!("Invalid hex symbol.")
    }
}

fn base64sym2digit(letter: &char) -> i32 {
    if letter.is_alphabetic() {
        if letter.is_lowercase() {
            return 26 + *letter as i32 - 'a' as i32;
        }
        return *letter as i32 - 'A' as i32;
    } else if letter.is_numeric() {
        return 52 + *letter as i32;
    } else if *letter == '+' {
        return 62;
    } else if *letter == '/' {
        return 63;
    } else {
        panic!("Invalid base64 character.");
    }
}

fn digit2base64sym(digit: &i32) -> String {
    if *digit < 0 || *digit > 63 {
        panic!("Invalid base64 character.");
    }
    if *digit >= 0 && *digit < 26 {
        return ((65 + digit) as u8 as char)
            .to_string();
    } else if *digit < 52 {
        return ((97 + digit - 26) as u8 as char)
            .to_string();
    } else if *digit < 62 {
        return (digit - 52).to_string();
    } else if *digit == 62 {
        return String::from('+');
    }
    return String::from('/');
}

fn digit2hexsym(digit: &i32) -> String {
    if *digit < 0 || *digit > 15 {
        panic!("Invalid hex character.");
    }
    if *digit < 10 {
        return format!("{}", *digit);
    }
    return String::from(HEXCHARS
                            .chars()
                            .nth((*digit - 10) as usize)
                            .unwrap());
}

fn hextobin(num_str: &String) -> String {
    num_str
        .chars()
        .map(|el| format!("{:04b}", hexsym2digit(&el)))
        .collect::<Vec<String>>()
        .join("")
}

fn base64tobin(num_str: &String) -> String {
    num_str
        .chars()
        .map(|el| format!("{:06b}", base64sym2digit(&el)))
        .collect::<Vec<String>>()
        .join("")
}

fn bintobase64(num_str: &String) -> String {
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

fn bintohex(num_str: &String) -> String {
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

pub fn hex2base64(hex: &String) -> String {
    let binding = hextobin(hex);
    let (_, hex_bin) = binding.split_once('1').unwrap();
    println!("{}", hex_bin);
    bintobase64(&format!("1{}", hex_bin))
}

pub fn base64tohex(base64: &String) -> String {
    let binding = base64tobin(base64);
    let (_, base64_bin) = binding.split_once('1').unwrap();
    println!("{}", base64_bin);
    bintohex(&format!("1{}", base64_bin))
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
    fn test_hex2base64() {
        let hex = String::from("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d");
        let base64 = String::from("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t");
        assert_eq!(hex2base64(&hex), base64);
    }

    #[test]
    fn test_base64tohex() {
        let hex = String::from("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d");
        let base64 = String::from("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t");
        assert_eq!(base64tohex(&base64), hex);
    }
}
