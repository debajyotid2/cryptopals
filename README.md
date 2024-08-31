# Cryptopals in Rust

The [cryptopals](https://cryptopals.com/) challenge is a set of exercises designed to introduce one to vulnerabilities in modern cryptographic algorithms (for example, variants of the [Advanced Encryption Standard (AES)](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)) and how to exploit them. These have been solved here using Rust. 

There are currently eight problem sets. The ones checkmarked below are the ones that I have finished:
- [x] [Set 1: Basics](sets/set1/README.md)
- [x] [Set 2: Block crypto](sets/set2/README.md)
- [x] [Set 3: Block and stream crypto](sets/set3/README.md)
- [x] [Set 4: Stream crypto and randomness](sets/set4/README.md)
- [x] [Set 5: Diffie-Hellman and friends](sets/set5/README.md)
- [x] [Set 6: RSA and DSA](sets/set6/README.md)
- [ ] Set 7: Hashes
- [ ] Set 8: Abstract Algebra

## Project organization

The problem sets are inside the folder `sets`.
```
sets
├── set1
│   ├── 4.txt
│   ├── 6.txt
│   ├── 7.txt
│   ├── 8.txt
│   ├── Cargo.toml
│   ├── macbeth.txt
│   ├── README.md
│   ├── src
│       └── main.rs
├── set2
│   ├── 10.txt
│   ├── Cargo.toml
│   ├── README.md
│   ├── src
│       ├── lib.rs
│       └── main.rs
├── set3
│   ├── 20.txt
│   ├── Cargo.toml
│   ├── README.md
│   ├── src
│       ├── lib.rs
│       └── main.rs
├── set4
│   ├── 25.txt
│   ├── Cargo.toml
│   ├── README.md
│   ├── src
│       ├── client.rs
│       ├── lib.rs
│       └── main.rs
├── set5
│   ├── Cargo.toml
│   ├── README.md
│   ├── src
│       ├── lib.rs
│       └── main.rs
└── set6
    ├── 44.txt
    ├── Cargo.toml
    ├── README.md
    ├── src
        ├── lib.rs
        └── main.rs

```
The remaining folders at the top level directory are libraries that are used within the problem set solution code.

## Quickstart

### Getting started with Rust

The Rust lang [website](https://www.rust-lang.org/learn/get-started) has an excellent guide on how to download and install Rust and its build tool - Cargo. This project uses Rust version 1.80.0.

### How to build/run

Each set is its own crate, with the dependencies defined in the `Cargo.toml` file within each crate. To fetch all dependencies for a particular set, say Set 1, please run
```
cd sets/set1
cargo fetch
```
The `src` folder of each crate contains the main program `main.rs`, which contains functions that set up each challenge problem and its solution. The main program uses library functions defined within `lib.rs` and from the crates at the top level directory. To run the solutions to all problems that belong to a set (e.g. Set 1), simply run
```
cd sets/set1
cargo run
```
To build all libraries as well as code for all problem sets, please run (from the root level)
```
cargo build
```
The functions in `lib.rs` for each set have unit tests defined. To run these unit tests (e.g. for Set 1), please run
```
cd sets/set1
cargo test
```
To run unit tests for all crates in the repository, from the root level directory, please run
```
cargo test
```

**NB.** These are general instructions. If these do not work for a particular problem set, please refer to specific instructions in the README in its directory.

## License

AGPL 3.0
