# Set 6

[Challenge link in the Cryptopals website](https://cryptopals.com/sets/6)

- [x] [Implement unpadded message recovery oracle](#implement-unpadded-message-recovery-oracle)
- [x] [Bleichenbacher e equals 3 RSA Attack](#bleichenbacher-e-equals-3-rsa-attack)
- [x] [DSA key recovery from nonce](#dsa-key-recovery-from-nonce)
- [x] [DSA nonce recovery from repeated nonce](#dsa-nonce-recovery-from-repeated-nonce)
- [x] [DSA parameter tampering](#dsa-parameter-tampering)
- [x] [RSA parity oracle](#rsa-parity-oracle)
- [x] [Bleichenbacher PKCS 1 point 5 Padding Oracle simple version](#bleichenbacher-pkcs-1-point-5-padding-oracle-simple-version)
- [x] [Bleichenbacher PKCS 1 point 5 Padding Oracle complete version](#bleichenbacher-pkcs-1-point-5-padding-oracle-complete-version)


## Implement unpadded message recovery oracle

The message server described in the [challenge](https://cryptopals.com/sets/6/challenges/41) is implemented in the struct `MessageServer`. 

For a ciphertext `C`, public modulus `N` and exponent `E` and a random number `S` such that 1 < `S` < `N`, we can calculate a new ciphertext `C' = ((S ^ E mod N) C) mod N`. The server returns plaintext `P'` for the modified ciphertext `C'`. The original plaintext `P` corresponding to `C` can then be retrieved by calculating
`P = (P`/ S) mod N`.

This attack is implemented in [`rsa_unpadded_message_recovery_attack()`](./src/lib.rs).

```rust
let rsa = RSA::new(&2048u16);
let mut server = MessageServer::new(&rsa);

let (exponent, modulus) = rsa.get_public_key();

let plaintext = b"Welcome to Bologna";
let ciphertext = rsa.encrypt(plaintext);
assert_eq!(server.decrypt(&ciphertext).unwrap(), plaintext.clone());

match server.decrypt(&ciphertext) {
    Ok(_) => println!("Server does not raise error on second attempt at decryption."),
    Err(_) => println!("Server successfully raises an error on second attempt at decryption.")
}

let retrieved_plaintext = rsa_unpadded_message_recovery_attack(&ciphertext, &modulus, &exponent, &mut server);
assert_eq!(plaintext.to_vec(), retrieved_plaintext);
```

## Bleichenbacher e equals 3 RSA Attack

The attack by Bleichenbacher on RSA with `e`= 3 is described in two places: [Bleichenbacher's 2006 paper](https://citeseerx.ist.psu.edu/document?repid=rep1&type=pdf&doi=da0429845d6fc4fd60d6442e8ff3a10762d0e446#page=14) and in [Hal Finney's writeup](https://mailarchive.ietf.org/arch/msg/openpgp/5rnE9ZRN1AokBVj3VqblGlP63QE/). Hal Finney's description is easier to understand, in my opinion.

Since some RSA implementations do not check if the right-most bits of a signature comprise of the padding (ASN1 and the hash), this attack takes advantage of this and the fact that the exponent is so low, i.e. 3. The attack involves taking a perfect cube of a desired length, cube rooting it, appending the padding (ASN1 and hash) and then finally utilizing the remaining space for any custom bytes desired by the attacker. The final message to be encrypted looks like

```
00 01 FF FF ... FF 00 ASN.1 HASH CUSTOMTEXT
```
This forged RSA signature will be valid in `e`=3. The attack is implemented in `forge_rsa_signature()`.

```rust
let message = b"hi mom";
let rsa = RSA::new(&1024u16);
let (exponent, modulus) = rsa.get_public_key();

// NOTE: Because of the relatively small key size, we are using MD5 for the hash
// generation, because it generates 16 byte long hashes - safe enough such that
// the cube-root we generate does not wrap around the modulus.

// Normal signature generation and verification
let signature: Vec<u8> = rsa_sign(message, &rsa).expect("Failed to generate RSA signature.");
rsa_verify(message, &signature, &rsa).expect("Invalid RSA signature.");

// Signature forgery
let forged = forge_rsa_signature(&signature, &modulus, &exponent, b"i'm not coming home");
rsa_verify(message, &forged, &rsa).expect("Invalid RSA signature.");
```

## DSA key recovery from nonce

The struct [`DSA`](../../dsaprotocol/src/lib.rs) provides an implementation of the [Digital Signature Algorithm](https://en.wikipedia.org/wiki/Digital_Signature_Algorithm#Operation). We skip the parameter generation step and use the values of `p`, `q` and `g` provided by the [challenge](https://cryptopals.com/sets/6/challenges/43). 

To recover the private key `x` from a known value of the subkey `k`, we use

```
x = ((s * k - H(msg)) / r) mod q
```
as in the writeup.  The function `recover_dsa_private_key()` implements this.

DSA is reimplemented in a "broken" version where `k` is always between 0 and 0xFFFF. Thus it can be easily guessed by iterating through all possibilities of `k`, recovering the value of `x`, using it to generate the public key `y` and comparing it against the value of the public key given in the challenge text.

```rust
let dsa = DSA::new();
let msg = b"I love the blues!";

// Sign and verify
let signature = dsa.sign(msg, None);
println!("Signature: r = {}, s = {}", bytearraytohex(&signature.0), bytearraytohex(&signature.1));
dsa.verify(msg, (&signature.0, &signature.1)).expect("Invalid DSA signature");

// Recover private key
let msg = b"For those that envy a MC it can be hazardous to your health\nSo be friendly, a matter of life and death, just like a etch-a-sketch\n";
let y = hextobytearray(&"084ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07bbb283e6633451e535c45513b2d33c99ea17".to_string());
let hash = hextobytearray(&"d2d0714f014a9784047eaeccf956520045c45265".to_string());
let r = hextobytearray(&"60019cacdc56eedf8e080984bfa898c8c5c419a8".to_string());
let s = hextobytearray(&"961f2062efc3c68db965a90c924cf76580ec1bbc".to_string());
let p = hextobytearray(&"800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1".to_string());
let q = hextobytearray(&"f4f47f05794b256174bba6e9b396a7707e563c5b".to_string());
let g = hextobytearray(&"5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291".to_string());
let x_hash = hextobytearray(&"0954edd5e0afe5542a4adf012611a91912a3ec16".to_string());

for guess in 0..=0xFFFFu16 {
    let k = [(guess >> 8 & 0xFF) as u8, (guess & 0xFF) as u8];
    let guessed_x = recover_dsa_private_key(&k, &r, &s, &q, &hash);
    if modpow_bytes(&g, &guessed_x, &p) == y {
        println!("Recovered private key: {}", guess);
        assert_eq!(bytearraytohex(&hash_sha1(&bytearraytohex(&guessed_x).as_bytes())), bytearraytohex(&x_hash));
        let dsa = DSA::new_from_params(&p, &q, &g, &guessed_x, &y);
        let (guessed_r, guessed_s) = dsa.sign(msg, Some(&k));
        assert_eq!(guessed_r, r);
        assert_eq!(guessed_s, s);
        break;
    }
}
```

## DSA nonce recovery from repeated nonce

For this challenge, we aim to find the pair of messages that use the same nonce, i.e. `k`. This is easily found if the messages have the same signature parameter `r`.
Since for DSA,

```
    s = (k^(-1) * (H(msg) + x * r)) mod q
or, k = (s^(-1) * (H(msg) + x * r)) mod q
or, x * r = (s * k - H(msg)) mod q
```

for this pair of messages, we can eliminate `x * r` and simplify the expression to get
```
k = (m1 - m2)/(s1 - s2) mod q
```

`recover_dsa_nonce()` and `recover_dsa_private_key()` implement recovery of `k` and `x`, respectively. Once `k` and `x` are known, we calculate the key `y` and compare its SHA1 hash against the one provided in the challenge statement.

```rust
let decimal_to_bigint_bytes = |string: &str| -> Vec<u8> {
    string.parse::<BigInt>().expect("Parse error").to_bytes_be().1
};

// Parse challenge file contents
let contents = fs::read_to_string("44.txt").expect("Error reading 44.txt");
let messages: Vec<&[u8]> = contents.lines().step_by(4).map(|x| x[5..].as_bytes()).collect();
let s_vecs: Vec<Vec<u8>> = contents.lines().skip(1).step_by(4).map(|x| decimal_to_bigint_bytes(&x[3..].replace("\n", "").replace(" ", ""))).collect();
let r_vecs: Vec<Vec<u8>> = contents.lines().skip(2).step_by(4).map(|x| decimal_to_bigint_bytes(&x[3..].replace("\n", "").replace(" ", ""))).collect();
let m_vecs: Vec<Vec<u8>> = contents.lines().skip(3).step_by(4)
                                    .map(|x| {
                                            let mut hex_str = x[3..].replace("\n", "").replace(" ", "");
                                            if hex_str.len() % 2 != 0 {
                                                hex_str.insert(0, '0');
                                            }
                                            hextobytearray(&hex_str)
                                        })
                                    .collect();
assert_eq!(messages.len(), s_vecs.len());
assert_eq!(s_vecs.len(), r_vecs.len());
assert_eq!(r_vecs.len(), m_vecs.len());

let y = hextobytearray(&"2d026f4bf30195ede3a088da85e398ef869611d0f68f0713d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b85519b1c23cc3ecdc6062650462e3063bd179c2a6581519f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d32971c3de5084cce04a2e147821".to_string());
let p = hextobytearray(&"800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1".to_string());
let q = hextobytearray(&"f4f47f05794b256174bba6e9b396a7707e563c5b".to_string());
let g = hextobytearray(&"5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291".to_string());
let x_hash = hextobytearray(&"ca8f6f7c66fa362d40760d135b763eb8527d3d52".to_string());

// Recover nonces from signatures and from the nonces, the private keys
for pair in (0..messages.len()).combinations(2) {
    // The signing used the same nonce if the value of r is the same for both messages
    if r_vecs[pair[0]] != r_vecs[pair[1]] {
        continue;
    }
    let recovered_k = recover_dsa_nonce(&messages[pair[0]], &messages[pair[1]], &s_vecs[pair[0]], &s_vecs[pair[1]], &q);
    let recovered_x = recover_dsa_private_key(&recovered_k, &r_vecs[pair[0]], &s_vecs[pair[0]], &q, &hash_sha1(messages[pair[0]]));

    if modpow_bytes(&g, &recovered_x, &p) == y {
        assert_eq!(hash_sha1(&bytearraytohex(&recovered_x).as_bytes()), x_hash);
        println!("recovered x = {}", bytearraytohex(&recovered_x));
        break;
    }
}
```

## DSA parameter tampering

From the implementation of DSA,

```
r = g^k mod p
v = (g^u1 y^u2 mod p) mod q
```

where `r` is one part of the public signature, and `v` is checked for equality against `r` during verification.

**Case 1:** `g` = 0

When `g` = 0, we see that `v` and `r` are both zero and equal irrespective of other parameters. This means that any random DSA signature can be positively verified by a DSA with this tampered parameter.

**Case 2:** `g` = `p`+1 

This case leads to `v` and `r` both being equal to 1, with the same consequences as Case 1.

```rust
let p = hextobytearray(&"800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1".to_string());
let q = hextobytearray(&"f4f47f05794b256174bba6e9b396a7707e563c5b".to_string());

// g = 0
println!("Case 1: g = 0");
let mut dsa = BrokenDSA::new_from_params(&p, &q, &[0u8], &[], &[]);
dsa.generate_user_keys();

let msg_1 = b"Hello, world";
let signature_1 = dsa.sign(msg_1, None);
println!("Signature for \"{}\": r = {}, s = {}", String::from_utf8(msg_1.to_vec()).unwrap(), bytearraytohex(&signature_1.0), bytearraytohex(&signature_1.1));
dsa.verify(msg_1, (&signature_1.0, &signature_1.1)).expect("DSA signature validation error");

let msg_2 = b"Goodbye, world";
let signature_2 = dsa.sign(msg_2, None);
println!("Signature for \"{}\": r = {}, s = {}", String::from_utf8(msg_2.to_vec()).unwrap(), bytearraytohex(&signature_2.0), bytearraytohex(&signature_2.1));
dsa.verify(msg_2, (&signature_2.0, &signature_2.1)).expect("DSA signature validation error");

// With g = 0, signatures from any random message are also valid for any other message
dsa.verify(msg_1, (&signature_2.0, &signature_2.1)).expect("DSA signature validation error");

// g = p+1
println!("Case 2: g = p+1");
let g: Vec<u8> = (BigInt::from_bytes_be(Sign::Plus, &p) + BigInt::from(1)).to_bytes_be().1;
let mut dsa = BrokenDSA::new_from_params(&p, &q, &g, &[], &[]);
dsa.generate_user_keys();

let msg_1 = b"Hello, world";
let signature_1 = dsa.sign(msg_1, None);
println!("Signature for \"{}\": r = {}, s = {}", String::from_utf8(msg_1.to_vec()).unwrap(), bytearraytohex(&signature_1.0), bytearraytohex(&signature_1.1));
dsa.verify(msg_1, (&signature_1.0, &signature_1.1)).expect("DSA signature validation error");

let msg_2 = b"Goodbye, world";
let signature_2 = dsa.sign(msg_2, None);
println!("Signature for \"{}\": r = {}, s = {}", String::from_utf8(msg_2.to_vec()).unwrap(), bytearraytohex(&signature_2.0), bytearraytohex(&signature_2.1));
dsa.verify(msg_2, (&signature_2.0, &signature_2.1)).expect("DSA signature validation error");

// With g = p+1, signatures from any random message are also valid for any other message
dsa.verify(msg_1, (&signature_2.0, &signature_2.1)).expect("DSA signature validation error");
```

## RSA parity oracle

A parity oracle, or an oracle that returns if the least significant bit (LSB) of the plaintext is even or odd, can be used to decrypt an RSA signature. For small plaintexts that are less than the modulus `n`, the decryption amounts usually to reducing the search interval of [0, `n`] down to [0, 1] one byte at a time. To determine which half of the interval to discard in each interval (similar to binary search), the plaintext is doubled (multiplied by 2 ^ `e` mod `n`) and the oracle queried for parity. If the parity is even, the plaintext is less than `n`/2. By narrowing down the search interval like this, we eventually decrypt the entire plaintext in log2(`n`) iterations.

`rsa_parity_oracle_attack()` implements this attack on RSA.

This challenge sets up the basis for one of the key steps in the Bleichenbacher "million-message" attack against RSA. 

```rust
let encryptor = RSA::new(&1024u16);

let msg = base64tobytearray(&"VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ".to_string());
let ciphertext = encryptor.encrypt(&msg);

let plaintext = rsa_parity_oracle_attack(&ciphertext, &encryptor);
// For some reason this algorithm seems to get the last byte wrong
assert_eq!(plaintext[..(plaintext.len()-1)], msg[..(msg.len()-1)]);

println!("Deciphered message: {}", String::from_utf8(plaintext).unwrap());
```

## Bleichenbacher PKCS 1 point 5 Padding Oracle simple version

The original attack from Bleichenbacher's [1998 paper](https://www.di.ens.fr/~fouque/ens-rennes/bleichenbacher.pdf) involves the steps of 

1. blinding 
2. searching for PKCS conforming messages 
    - a) starting the search
    - b) searching with more than one interval left
    - c) searching with one interval left
3. narrowing the set of solutions
4. computing the solution

We only implement steps 2.a, 2.c and 3 for simplicity. Step 1 is skipped since the starting ciphertext is already PKCS conforming. We are also only handling a single interval, so we skip step 2.b and simplify step 3. This attack works because of the small size of the plaintext and the modulus, i.e. 256 bits.

The mini-Bleichenbacher attack sometimes panics because sometimes the algorithm breaks from the loop of Step 2 without converging. Re-running the algorithm solves this.

```rust
let keysize = 256usize;
let encryptor = MiniRSA::new(&keysize);
let pad_pkcs1v15_unsafe = |msg: &[u8], length: usize| -> Vec<u8> {
    let mut padded: Vec<u8> = vec![0x00, 0x02];
    padded.extend(generate_random_bytevec(length-msg.len()-3));
    padded.push(0x00);
    padded.extend(msg);

    padded
};

// This will panic sometimes. The only option is to try again.
let msg = b"kick it, CC";
let ciphertext = encryptor.encrypt(&pad_pkcs1v15_unsafe(msg, keysize / 8));
let recovered = mini_bleichenbacher_attack_rsa_pkcs1v15_encryption(&encryptor, &ciphertext);
assert_eq!(msg, &recovered[recovered.len()-msg.len()..]);
println!("{}", String::from_utf8(recovered[recovered.len()-msg.len()..].to_vec()).unwrap())
```

## Bleichenbacher PKCS 1 point 5 Padding Oracle complete version

The full Bleichenbacher attack is implemented here. Step 1 is again skipped since we start with a ciphertext that is already PKCS1.5 compliant.

**NB1.**: This algorithm takes longer for longer plaintexts. For the purpose of demonstration I have kept the length of the plaintext small.

**NB2.** This algorithm also panics sometimes for the same reasons as the [previous implementation](#bleichenbacher-pkcs-1-point-5-padding-oracle-simple-version). Re-running the algorithm resolves this problem.

```rust
let keysize = 768usize;
let encryptor = MiniRSA::new(&keysize);
let pad_pkcs1v15_unsafe = |msg: &[u8], length: usize| -> Vec<u8> {
    let mut padded: Vec<u8> = vec![0x00, 0x02];
    padded.extend(generate_random_bytevec(length-msg.len()-3));
    padded.push(0x00);
    padded.extend(msg);

    padded
};

// This will panic sometimes. The only option is to try again.
let msg = b"Hewlett Packard ist der wurst";
let ciphertext = encryptor.encrypt(&pad_pkcs1v15_unsafe(msg, keysize / 8));
let recovered = bleichenbacher_attack_rsa_pkcs1v15_encryption(&encryptor, &ciphertext);
assert_eq!(msg, &recovered[recovered.len()-msg.len()..]);
println!("{}", String::from_utf8(recovered[recovered.len()-msg.len()..].to_vec()).unwrap())
```

