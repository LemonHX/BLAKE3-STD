![blake3](BLAKE3.svg)
# BLAKE3-STD
> the first blake3 implementation on `std::simd`

## OFFICIAL DOC
BLAKE3 is a cryptographic hash function that is:

- Much faster than MD5, SHA-1, SHA-2, SHA-3, and BLAKE2.
- Secure, unlike MD5 and SHA-1. And secure against length extension, unlike SHA-2.
- Highly parallelizable across any number of threads and SIMD lanes, because it's a Merkle tree on the inside.
- Capable of verified streaming and incremental updates, again because it's a Merkle tree.
- A PRF, MAC, KDF, and XOF, as well as a regular hash.
- One algorithm with no variants, which is fast on x86-64 and also on smaller architectures.

BLAKE3 was designed by:

- @oconnor663 (Jack O'Connor)
- @sneves (Samuel Neves)
- @veorq (Jean-Philippe Aumasson)
- @zookozcash (Zooko)

The development of BLAKE3 was sponsored by the Electric Coin Company.

## AT THE SAME TIME THANKS TO RUST MERGED `portable_simd`
which means it could run on any platform that `LLVM` has SIMD implementation.

## BENCHMARKS
could be found at [github pages](https://lemonhx.moe/BLAKE3-STD/)

## USAGE
same as the official one

## TODO
- [ ] Implement SIMD for hash4
- [ ] DOCS
- [ ] reformats
