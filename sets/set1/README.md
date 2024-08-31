# Set 1

[Challenge link in the Cryptopals website](https://cryptopals.com/sets/1)

- [x] [Convert hex to base64](#convert-hex-to-base64)
- [x] [Fixed XOR](#fixed-xor)
- [x] [Single-byte XOR cipher](#single-byte-xor-cipher)
- [x] [Detect single-character XOR](#detect-single-character-xor)
- [x] [Implement repeating-key XOR](#implement-repeating-key-xor)
- [x] [Break repeating-key XOR](#break-repeating-key-xor)
- [x] [AES in ECB mode](#aes-in-ecb-mode)
- [x] [Detect AES in ECB mode](#detect-aes-in-ecb-mode)

## Convert hex to base64

This is done within one of the unit tests in [`bytearrayconversion`](../../bytearrayconversion/src/lib.rs).
```rust
let hex = String::from("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d");
let base64 = String::from("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t");
assert_eq!(hextobase64(&hex), base64);
```

## Fixed XOR

This is tested in one of the unit tests in [`xorcipher`](../../xorcipher/src/helpers.rs).
```rust
let hex1 = String::from("1c0111001f010100061a024b53535009181c");
let hex2 = String::from("686974207468652062756c6c277320657965");
assert_eq!(hex_xor(&hex1, &hex2), String::from("746865206b696420646f6e277420706c6179"));
assert_eq!(hex_xor(&hex2, &hex1), String::from("746865206b696420646f6e277420706c6179"));
```

## Single-byte XOR cipher

Using a frequency histogram of the English alphabet and a scoring scheme, [`decrypt_singlebyte_xor_faster()`](../../xorcipher/src/lib.rs) ranks the the bytes that are most probable to be the keys of a single-byte XOR cipher.
```rust
let plaintext = fs::read_to_string("macbeth.txt").unwrap();
let key = 216u8;
let ciphertext = encrypt_singlebyte_xor(&plaintext, key);
let matches = decrypt_singlebyte_xor_faster(&ciphertext);
for count in 0..5 {
    if matches[count].plaintext == None {
        continue;
    }
    println!("----------------------------------------");
    println!("Match {}: {}", count + 1, 
        &matches[count].plaintext.as_ref().unwrap()[0..100]);
}
```

## Detect single-character XOR

[`decrypt_singlebyte_xor()`](../../xorcipher/src/lib.rs) finds out which of the lines in a text file have been encrypted using single byte XOR cipher, and decrypts them.
```rust
let ciphertext = fs::read_to_string("4.txt").unwrap();
for (lineno, line) in ciphertext.lines().enumerate() {
    let matches = decrypt_singlebyte_xor(&line.to_string());
    for count in 0..2 {
        if matches[count].plaintext == None {
            continue;
        }
        println!("----------------------------------------------");
        println!("Line {}, Match {}: {}", 
            lineno + 1, count + 1, &matches[count].plaintext
                                                .as_ref().unwrap());
    }
}
```

## Implement repeating-key XOR

[`encrypt_repeatingkey_xor()`](../../xorcipher/src/lib.rs) takes a sequence of bytes (key) and repeatedly XORs them against the plaintext to encrypt it. The code is part of the unit tests.

```rust
let plaintext = String::from("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal");
let key = String::from("ICE");
assert_eq!(encrypt_repeatingkey_xor(&plaintext, &key), 
            String::from("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"));
```

## Break repeating-key XOR

Repeating key XOR is broken in a similar fashion as the single byte XOR is broken, by framing the repeating key XOR encryption as a collection of single byte XOR encryption tasks.([`encrypt_repeatingkey_xor()`](../../xorcipher/src/lib.rs))

```rust
let ciphertext = fs::read_to_string("6.txt")
                        .unwrap_or(String::new())
                        .replace("\n", "")
                        .replace("=", "");
let keys_and_scores = decrypt_repeatingkey_xor(&base64tobytearray(&ciphertext));
let ascii_ciphertext: String = String::from_utf8(base64tobytearray(&ciphertext)).unwrap_or(String::new());                       
let key: &String = &keys_and_scores[0].0;
println!("Key = {}", &key);

println!("------------------------------------------------------");
println!("Match: {}", String::from_utf8(hextobytearray(
            &encrypt_repeatingkey_xor(&ascii_ciphertext, key))).unwrap());
```

## AES in ECB mode

Here a library function is used from the [`aes`](https://docs.rs/aes/latest/aes/) crate to decrypt AES-ECB encryption. ([`decrypt_aes_ecb()`](../../aescipher/src/lib.rs))

```rust
let base64_ciphertext = fs::read_to_string("7.txt")
                        .unwrap_or(String::new())
                        .replace("\n", "")
                        .replace("=", "");
let ascii_key = String::from("YELLOW SUBMARINE");
let decrypted: Vec<u8> = decrypt_aes_ecb(&base64tobytearray(&base64_ciphertext),
                            &ascii_key.as_bytes().to_vec());

println!("Decrypted: \n{}", String::from_utf8(decrypted).unwrap());
```

## Detect AES in ECB mode

[`detect_aes_ecb_encryption()`](../../aescipher/src/lib.rs) finds out if a ciphertext is AES-ECB encrypted by checking for repeating blocks.

```rust
let hex_ciphertext = fs::read_to_string("8.txt")
                        .unwrap_or(String::new());
let lineno = detect_aes_ecb_encryption(&hex_ciphertext);

if lineno == 0 {
    return;
}
println!("Found! Line number {} is AES ECB encrypted.", lineno);

```

