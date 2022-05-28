#![feature(portable_simd)]
#![feature(stdsimd)]
#![feature(repr_simd)]
#![feature(array_windows)]
#![feature(stdarch)]
#![allow(dead_code)]
use arrayvec::{ArrayString, ArrayVec};
use fallback::compress_in_place;

use std::{cmp, fmt};

use crate::arith::hash_many;
pub mod arith;
pub mod fallback;
mod join;
pub mod reference_impl;
#[cfg(test)]
mod test;
#[macro_export]
macro_rules! array_mut_ref {
    ($arr:expr, $offset:expr, $len:expr) => {{
        {
            #[inline]
            unsafe fn as_array<T>(slice: &mut [T]) -> &mut [T; $len] {
                &mut *(slice.as_mut_ptr() as *mut [_; $len])
            }
            let offset = $offset;
            let slice = &mut $arr[offset..offset + $len];
            #[allow(unused_unsafe)]
            unsafe {
                as_array(slice)
            }
        }
    }}
}
#[macro_export]
macro_rules! array_ref {
    ($arr:expr, $offset:expr, $len:expr) => {{
        {
            #[inline]
            unsafe fn as_array<T>(slice: &[T]) -> &[T; $len] {
                &*(slice.as_ptr() as *const [_; $len])
            }
            let offset = $offset;
            let slice = & $arr[offset..offset + $len];
            #[allow(unused_unsafe)]
            unsafe {
                as_array(slice)
            }
        }
    }}
}

const MAX_DEPTH: usize = 54;

const MSG_SCHEDULE: [[usize; 16]; 7] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8],
    [3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1],
    [10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6],
    [12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4],
    [9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7],
    [11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13],
];

const CHUNK_START: u8 = 1 << 0;
const CHUNK_END: u8 = 1 << 1;
const PARENT: u8 = 1 << 2;
const ROOT: u8 = 1 << 3;
const KEYED_HASH: u8 = 1 << 4;
const DERIVE_KEY_CONTEXT: u8 = 1 << 5;
const DERIVE_KEY_MATERIAL: u8 = 1 << 6;

type CVWords = [u32; 8];
type CVBytes = [u8; 32];

const IV: &CVWords = &[
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];

pub const BLOCK_LEN: usize = 64;
pub const CHUNK_LEN: usize = 1024;

pub const KEY_LEN: usize = 32;
pub const OUT_LEN: usize = 32;

#[inline(always)]
pub fn words_from_le_bytes_32(bytes: &[u8; 32]) -> [u32; 8] {
    let mut out = [0; 8];
    out[0] = u32::from_le_bytes(*array_ref!(bytes, 0 * 4, 4));
    out[1] = u32::from_le_bytes(*array_ref!(bytes, 1 * 4, 4));
    out[2] = u32::from_le_bytes(*array_ref!(bytes, 2 * 4, 4));
    out[3] = u32::from_le_bytes(*array_ref!(bytes, 3 * 4, 4));
    out[4] = u32::from_le_bytes(*array_ref!(bytes, 4 * 4, 4));
    out[5] = u32::from_le_bytes(*array_ref!(bytes, 5 * 4, 4));
    out[6] = u32::from_le_bytes(*array_ref!(bytes, 6 * 4, 4));
    out[7] = u32::from_le_bytes(*array_ref!(bytes, 7 * 4, 4));
    out
}

#[inline(always)]
pub fn words_from_le_bytes_64(bytes: &[u8; 64]) -> [u32; 16] {
    let mut out = [0; 16];
    out[0] = u32::from_le_bytes(*array_ref!(bytes, 0 * 4, 4));
    out[1] = u32::from_le_bytes(*array_ref!(bytes, 1 * 4, 4));
    out[2] = u32::from_le_bytes(*array_ref!(bytes, 2 * 4, 4));
    out[3] = u32::from_le_bytes(*array_ref!(bytes, 3 * 4, 4));
    out[4] = u32::from_le_bytes(*array_ref!(bytes, 4 * 4, 4));
    out[5] = u32::from_le_bytes(*array_ref!(bytes, 5 * 4, 4));
    out[6] = u32::from_le_bytes(*array_ref!(bytes, 6 * 4, 4));
    out[7] = u32::from_le_bytes(*array_ref!(bytes, 7 * 4, 4));
    out[8] = u32::from_le_bytes(*array_ref!(bytes, 8 * 4, 4));
    out[9] = u32::from_le_bytes(*array_ref!(bytes, 9 * 4, 4));
    out[10] = u32::from_le_bytes(*array_ref!(bytes, 10 * 4, 4));
    out[11] = u32::from_le_bytes(*array_ref!(bytes, 11 * 4, 4));
    out[12] = u32::from_le_bytes(*array_ref!(bytes, 12 * 4, 4));
    out[13] = u32::from_le_bytes(*array_ref!(bytes, 13 * 4, 4));
    out[14] = u32::from_le_bytes(*array_ref!(bytes, 14 * 4, 4));
    out[15] = u32::from_le_bytes(*array_ref!(bytes, 15 * 4, 4));
    out
}

#[inline(always)]
pub fn le_bytes_from_words_32(words: &[u32; 8]) -> [u8; 32] {
    let mut out = [0; 32];
    *array_mut_ref!(out, 0 * 4, 4) = words[0].to_le_bytes();
    *array_mut_ref!(out, 1 * 4, 4) = words[1].to_le_bytes();
    *array_mut_ref!(out, 2 * 4, 4) = words[2].to_le_bytes();
    *array_mut_ref!(out, 3 * 4, 4) = words[3].to_le_bytes();
    *array_mut_ref!(out, 4 * 4, 4) = words[4].to_le_bytes();
    *array_mut_ref!(out, 5 * 4, 4) = words[5].to_le_bytes();
    *array_mut_ref!(out, 6 * 4, 4) = words[6].to_le_bytes();
    *array_mut_ref!(out, 7 * 4, 4) = words[7].to_le_bytes();
    out
}

#[inline(always)]
pub fn le_bytes_from_words_64(words: &[u32; 16]) -> [u8; 64] {
    let mut out = [0; 64];
    *array_mut_ref!(out, 0 * 4, 4) = words[0].to_le_bytes();
    *array_mut_ref!(out, 1 * 4, 4) = words[1].to_le_bytes();
    *array_mut_ref!(out, 2 * 4, 4) = words[2].to_le_bytes();
    *array_mut_ref!(out, 3 * 4, 4) = words[3].to_le_bytes();
    *array_mut_ref!(out, 4 * 4, 4) = words[4].to_le_bytes();
    *array_mut_ref!(out, 5 * 4, 4) = words[5].to_le_bytes();
    *array_mut_ref!(out, 6 * 4, 4) = words[6].to_le_bytes();
    *array_mut_ref!(out, 7 * 4, 4) = words[7].to_le_bytes();
    *array_mut_ref!(out, 8 * 4, 4) = words[8].to_le_bytes();
    *array_mut_ref!(out, 9 * 4, 4) = words[9].to_le_bytes();
    *array_mut_ref!(out, 10 * 4, 4) = words[10].to_le_bytes();
    *array_mut_ref!(out, 11 * 4, 4) = words[11].to_le_bytes();
    *array_mut_ref!(out, 12 * 4, 4) = words[12].to_le_bytes();
    out
}

#[derive(Clone, Copy, Hash)]
pub struct Hash([u8; OUT_LEN]);

impl Hash {
    #[inline]
    pub fn as_bytes(&self) -> &[u8; OUT_LEN] {
        &self.0
    }

    pub fn to_hex(&self) -> ArrayString<{ 2 * OUT_LEN }> {
        let mut s = ArrayString::new();
        let table = b"0123456789abcdef";
        for &b in self.0.iter() {
            s.push(table[(b >> 4) as usize] as char);
            s.push(table[(b & 0xf) as usize] as char);
        }
        s
    }

    pub fn from_hex(hex: impl AsRef<[u8]>) -> Result<Self, HexError> {
        fn hex_val(byte: u8) -> Result<u8, HexError> {
            match byte {
                b'A'..=b'F' => Ok(byte - b'A' + 10),
                b'a'..=b'f' => Ok(byte - b'a' + 10),
                b'0'..=b'9' => Ok(byte - b'0'),
                _ => Err(HexError(HexErrorInner::InvalidByte(byte))),
            }
        }
        let hex_bytes: &[u8] = hex.as_ref();
        if hex_bytes.len() != OUT_LEN * 2 {
            return Err(HexError(HexErrorInner::InvalidLen(hex_bytes.len())));
        }
        let mut hash_bytes: [u8; OUT_LEN] = [0; OUT_LEN];
        for i in 0..OUT_LEN {
            hash_bytes[i] = 16 * hex_val(hex_bytes[2 * i])? + hex_val(hex_bytes[2 * i + 1])?;
        }
        Ok(Hash::from(hash_bytes))
    }
}

impl From<[u8; OUT_LEN]> for Hash {
    #[inline]
    fn from(bytes: [u8; OUT_LEN]) -> Self {
        Self(bytes)
    }
}

impl From<Hash> for [u8; OUT_LEN] {
    #[inline]
    fn from(hash: Hash) -> Self {
        hash.0
    }
}

impl core::str::FromStr for Hash {
    type Err = HexError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Hash::from_hex(s)
    }
}

impl PartialEq for Hash {
    #[inline]
    fn eq(&self, other: &Hash) -> bool {
        {
            let a = &self.0;
            let b = &other.0;
            ({
                let mut tmp = 0;
                for i in 0..32 {
                    tmp |= a[i] ^ b[i];
                }
                tmp
            }) == 0
        }
    }
}

impl PartialEq<[u8; OUT_LEN]> for Hash {
    #[inline]
    fn eq(&self, other: &[u8; OUT_LEN]) -> bool {
        {
            let a = &self.0;
            ({
                let mut tmp = 0;
                for i in 0..32 {
                    tmp |= a[i] ^ other[i];
                }
                tmp
            }) == 0
        }
    }
}

impl PartialEq<[u8]> for Hash {
    #[inline]
    fn eq(&self, other: &[u8]) -> bool {
        {
            let a: &[u8] = &self.0;
            a.len() == other.len()
                && ({
                    let a = a;
                    let b = other;
                    assert!(a.len() == b.len());

                    let len = a.len();
                    let a = &a[..len];
                    let b = &b[..len];

                    let mut tmp = 0;
                    for i in 0..len {
                        tmp |= a[i] ^ b[i];
                    }
                    tmp
                }) == 0
        }
    }
}

impl Eq for Hash {}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let hex = self.to_hex();
        let hex: &str = hex.as_str();

        f.write_str(hex)
    }
}

impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let hex = self.to_hex();
        let hex: &str = hex.as_str();

        f.debug_tuple("Hash").field(&hex).finish()
    }
}
#[derive(Clone, Debug)]
pub struct HexError(HexErrorInner);

#[derive(Clone, Debug)]
enum HexErrorInner {
    InvalidByte(u8),
    InvalidLen(usize),
}

impl fmt::Display for HexError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.0 {
            HexErrorInner::InvalidByte(byte) => {
                if byte < 128 {
                    write!(f, "invalid hex character: {:?}", byte as char)
                } else {
                    write!(f, "invalid hex character: 0x{:x}", byte)
                }
            }
            HexErrorInner::InvalidLen(len) => {
                write!(f, "expected 64 hex bytes, received {}", len)
            }
        }
    }
}

impl std::error::Error for HexError {}

#[derive(Clone)]
struct Output {
    input_chaining_value: CVWords,
    block: [u8; 64],
    block_len: u8,
    counter: u64,
    flags: u8,
}

impl Output {
    fn chaining_value(&self) -> CVBytes {
        let mut cv = self.input_chaining_value;
        compress_in_place(
            &mut cv,
            &self.block,
            self.block_len,
            self.counter,
            self.flags,
        );
        le_bytes_from_words_32(&cv)
    }

    fn root_hash(&self) -> Hash {
        debug_assert_eq!(self.counter, 0);
        let mut cv = self.input_chaining_value;
        fallback::compress_in_place(&mut cv, &self.block, self.block_len, 0, self.flags | ROOT);
        Hash(le_bytes_from_words_32(&cv))
    }

    fn root_output_block(&self) -> [u8; 2 * OUT_LEN] {
        fallback::compress_xof(
            &self.input_chaining_value,
            &self.block,
            self.block_len,
            self.counter,
            self.flags | ROOT,
        )
    }
}

#[derive(Clone)]
struct ChunkState {
    cv: CVWords,
    chunk_counter: u64,
    buf: [u8; BLOCK_LEN],
    buf_len: u8,
    blocks_compressed: u8,
    flags: u8,
}

impl ChunkState {
    fn new(key: &CVWords, chunk_counter: u64, flags: u8) -> Self {
        Self {
            cv: *key,
            chunk_counter,
            buf: [0; BLOCK_LEN],
            buf_len: 0,
            blocks_compressed: 0,
            flags,
        }
    }

    fn len(&self) -> usize {
        BLOCK_LEN * self.blocks_compressed as usize + self.buf_len as usize
    }

    fn fill_buf(&mut self, input: &mut &[u8]) {
        let want = BLOCK_LEN - self.buf_len as usize;
        let take = std::cmp::min(want, input.len());
        self.buf[self.buf_len as usize..][..take].copy_from_slice(&input[..take]);
        self.buf_len += take as u8;
        *input = &input[take..];
    }

    fn start_flag(&self) -> u8 {
        if self.blocks_compressed == 0 {
            CHUNK_START
        } else {
            0
        }
    }

    fn update(&mut self, mut input: &[u8]) -> &mut Self {
        if self.buf_len > 0 {
            self.fill_buf(&mut input);
            if !input.is_empty() {
                debug_assert_eq!(self.buf_len as usize, BLOCK_LEN);
                let block_flags = self.flags | self.start_flag();
                fallback::compress_in_place(
                    &mut self.cv,
                    &self.buf,
                    BLOCK_LEN as u8,
                    self.chunk_counter,
                    block_flags,
                );
                self.buf_len = 0;
                self.buf = [0; BLOCK_LEN];
                self.blocks_compressed += 1;
            }
        }

        while input.len() > BLOCK_LEN {
            debug_assert_eq!(self.buf_len, 0);
            let block_flags = self.flags | self.start_flag();
            fallback::compress_in_place(
                &mut self.cv,
                array_ref!(input, 0, BLOCK_LEN),
                BLOCK_LEN as u8,
                self.chunk_counter,
                block_flags,
            );
            self.blocks_compressed += 1;
            input = &input[BLOCK_LEN..];
        }

        self.fill_buf(&mut input);
        debug_assert!(input.is_empty());
        debug_assert!(self.len() <= CHUNK_LEN);
        self
    }

    fn output(&self) -> Output {
        let block_flags = self.flags | self.start_flag() | CHUNK_END;
        Output {
            input_chaining_value: self.cv,
            block: self.buf,
            block_len: self.buf_len,
            counter: self.chunk_counter,
            flags: block_flags,
        }
    }
}

impl fmt::Debug for ChunkState {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("ChunkState")
            .field("len", &self.len())
            .field("chunk_counter", &self.chunk_counter)
            .field("flags", &self.flags)
            .finish()
    }
}

fn largest_power_of_two_leq(n: usize) -> usize {
    ((n / 2) + 1).next_power_of_two()
}

fn left_len(content_len: usize) -> usize {
    debug_assert!(content_len > CHUNK_LEN);

    let full_chunks = (content_len - 1) / CHUNK_LEN;
    largest_power_of_two_leq(full_chunks) * CHUNK_LEN
}

fn compress_chunks_parallel(
    input: &[u8],
    key: &CVWords,
    chunk_counter: u64,
    flags: u8,
    out: &mut [u8],
) -> usize {
    debug_assert!(!input.is_empty(), "empty chunks below the root");
    debug_assert!(input.len() <= 8 * CHUNK_LEN);

    let mut chunks_exact = input.chunks_exact(CHUNK_LEN);
    let mut chunks_array = ArrayVec::<&[u8; CHUNK_LEN], 8>::new();
    for chunk in &mut chunks_exact {
        chunks_array.push(array_ref!(chunk, 0, CHUNK_LEN));
    }
    hash_many(
        &chunks_array,
        key,
        chunk_counter,
        true,
        flags,
        CHUNK_START,
        CHUNK_END,
        out,
    );

    let chunks_so_far = chunks_array.len();
    if !chunks_exact.remainder().is_empty() {
        let counter = chunk_counter + chunks_so_far as u64;
        let mut chunk_state = ChunkState::new(key, counter, flags);
        chunk_state.update(chunks_exact.remainder());
        *array_mut_ref!(out, chunks_so_far * OUT_LEN, OUT_LEN) =
            chunk_state.output().chaining_value();
        chunks_so_far + 1
    } else {
        chunks_so_far
    }
}

fn compress_parents_parallel(
    child_chaining_values: &[u8],
    key: &CVWords,
    flags: u8,
    out: &mut [u8],
) -> usize {
    debug_assert_eq!(child_chaining_values.len() % OUT_LEN, 0, "wacky hash bytes");
    let num_children = child_chaining_values.len() / OUT_LEN;
    debug_assert!(num_children >= 2, "not enough children");
    debug_assert!(num_children <= 2 * 8, "too many");

    let mut parents_exact = child_chaining_values.chunks_exact(BLOCK_LEN);

    let mut parents_array = ArrayVec::<&[u8; BLOCK_LEN], 8>::new();
    for parent in &mut parents_exact {
        parents_array.push(array_ref!(parent, 0, BLOCK_LEN));
    }
    hash_many(&parents_array, key, 0, false, flags | PARENT, 0, 0, out);

    let parents_so_far = parents_array.len();
    if !parents_exact.remainder().is_empty() {
        out[parents_so_far * OUT_LEN..][..OUT_LEN].copy_from_slice(parents_exact.remainder());
        parents_so_far + 1
    } else {
        parents_so_far
    }
}

fn compress_subtree_wide<J: join::Join>(
    input: &[u8],
    key: &CVWords,
    chunk_counter: u64,
    flags: u8,
    out: &mut [u8],
) -> usize {
    if input.len() <= 8 * CHUNK_LEN {
        return compress_chunks_parallel(input, key, chunk_counter, flags, out);
    }

    let (left, right) = input.split_at(left_len(input.len()));
    let right_chunk_counter = chunk_counter + (left.len() / CHUNK_LEN) as u64;

    let mut cv_array = [0; 2 * 8 * OUT_LEN];
    let degree = if left.len() == CHUNK_LEN { 1 } else { 8 };
    let (left_out, right_out) = cv_array.split_at_mut(degree * OUT_LEN);

    let (left_n, right_n) = J::join(
        || compress_subtree_wide::<J>(left, key, chunk_counter, flags, left_out),
        || compress_subtree_wide::<J>(right, key, right_chunk_counter, flags, right_out),
    );

    debug_assert_eq!(left_n, degree);
    debug_assert!(right_n >= 1 && right_n <= left_n);
    if left_n == 1 {
        out[..2 * OUT_LEN].copy_from_slice(&cv_array[..2 * OUT_LEN]);
        return 2;
    }

    let num_children = left_n + right_n;
    compress_parents_parallel(&cv_array[..num_children * OUT_LEN], key, flags, out)
}

fn compress_subtree_to_parent_node<J: join::Join>(
    input: &[u8],
    key: &CVWords,
    chunk_counter: u64,
    flags: u8,
) -> [u8; BLOCK_LEN] {
    debug_assert!(input.len() > CHUNK_LEN);
    let mut cv_array = [0; 8 * OUT_LEN];
    let mut num_cvs = compress_subtree_wide::<J>(input, &key, chunk_counter, flags, &mut cv_array);
    debug_assert!(num_cvs >= 2);

    let mut out_array = [0; 8 * OUT_LEN / 2];
    while num_cvs > 2 {
        let cv_slice = &cv_array[..num_cvs * OUT_LEN];
        num_cvs = compress_parents_parallel(cv_slice, key, flags, &mut out_array);
        cv_array[..num_cvs * OUT_LEN].copy_from_slice(&out_array[..num_cvs * OUT_LEN]);
    }
    *array_ref!(cv_array, 0, 2 * OUT_LEN)
}

fn hash_all_at_once<J: join::Join>(input: &[u8], key: &CVWords, flags: u8) -> Output {
    if input.len() <= CHUNK_LEN {
        return ChunkState::new(key, 0, flags).update(input).output();
    }

    Output {
        input_chaining_value: *key,
        block: compress_subtree_to_parent_node::<J>(input, key, 0, flags),
        block_len: BLOCK_LEN as u8,
        counter: 0,
        flags: flags | PARENT,
    }
}

pub fn hash(input: &[u8]) -> Hash {
    hash_all_at_once::<join::SerialJoin>(input, IV, 0).root_hash()
}

pub fn keyed_hash(key: &[u8; KEY_LEN], input: &[u8]) -> Hash {
    let key_words = words_from_le_bytes_32(key);
    hash_all_at_once::<join::SerialJoin>(input, &key_words, KEYED_HASH).root_hash()
}

pub fn derive_key(context: &str, key_material: &[u8]) -> [u8; OUT_LEN] {
    let context_key =
        hash_all_at_once::<join::SerialJoin>(context.as_bytes(), IV, DERIVE_KEY_CONTEXT)
            .root_hash();
    let context_key_words = words_from_le_bytes_32(context_key.as_bytes());
    hash_all_at_once::<join::SerialJoin>(key_material, &context_key_words, DERIVE_KEY_MATERIAL)
        .root_hash()
        .0
}

fn parent_node_output(
    left_child: &CVBytes,
    right_child: &CVBytes,
    key: &CVWords,
    flags: u8,
) -> Output {
    let mut block = [0; BLOCK_LEN];
    block[..32].copy_from_slice(left_child);
    block[32..].copy_from_slice(right_child);
    Output {
        input_chaining_value: *key,
        block,
        block_len: BLOCK_LEN as u8,
        counter: 0,
        flags: flags | PARENT,
    }
}

#[derive(Clone)]
pub struct Hasher {
    key: CVWords,
    chunk_state: ChunkState,

    cv_stack: ArrayVec<CVBytes, { MAX_DEPTH + 1 }>,
}

impl Hasher {
    fn new_internal(key: &CVWords, flags: u8) -> Self {
        Self {
            key: *key,
            chunk_state: ChunkState::new(key, 0, flags),
            cv_stack: ArrayVec::<_, 55>::new(),
        }
    }

    pub fn new() -> Self {
        Self::new_internal(IV, 0)
    }

    pub fn new_keyed(key: &[u8; KEY_LEN]) -> Self {
        let key_words = words_from_le_bytes_32(key);
        Self::new_internal(&key_words, KEYED_HASH)
    }

    pub fn new_derive_key(context: &str) -> Self {
        let context_key =
            hash_all_at_once::<join::SerialJoin>(context.as_bytes(), IV, DERIVE_KEY_CONTEXT)
                .root_hash();
        let context_key_words = words_from_le_bytes_32(context_key.as_bytes());
        Self::new_internal(&context_key_words, DERIVE_KEY_MATERIAL)
    }

    pub fn reset(&mut self) -> &mut Self {
        self.chunk_state = ChunkState::new(&self.key, 0, self.chunk_state.flags);
        self.cv_stack.clear();
        self
    }

    fn merge_cv_stack(&mut self, total_len: u64) {
        let post_merge_stack_len = total_len.count_ones() as usize;
        while self.cv_stack.len() > post_merge_stack_len {
            let right_child = self.cv_stack.pop().unwrap();
            let left_child = self.cv_stack.pop().unwrap();
            let parent_output =
                parent_node_output(&left_child, &right_child, &self.key, self.chunk_state.flags);
            self.cv_stack.push(parent_output.chaining_value());
        }
    }

    fn push_cv(&mut self, new_cv: &CVBytes, chunk_counter: u64) {
        self.merge_cv_stack(chunk_counter);
        self.cv_stack.push(*new_cv);
    }

    pub fn update(&mut self, input: &[u8]) -> &mut Self {
        self.update_with_join::<join::SerialJoin>(input)
    }

    #[cfg(feature = "rayon")]
    pub fn update_rayon(&mut self, input: &[u8]) -> &mut Self {
        self.update_with_join::<join::RayonJoin>(input)
    }

    fn update_with_join<J: join::Join>(&mut self, mut input: &[u8]) -> &mut Self {
        if self.chunk_state.len() > 0 {
            let want = CHUNK_LEN - self.chunk_state.len();
            let take = cmp::min(want, input.len());
            self.chunk_state.update(&input[..take]);
            input = &input[take..];
            if !input.is_empty() {
                debug_assert_eq!(self.chunk_state.len(), CHUNK_LEN);
                let chunk_cv = self.chunk_state.output().chaining_value();
                self.push_cv(&chunk_cv, self.chunk_state.chunk_counter);
                self.chunk_state = ChunkState::new(
                    &self.key,
                    self.chunk_state.chunk_counter + 1,
                    self.chunk_state.flags,
                );
            } else {
                return self;
            }
        }

        while input.len() > CHUNK_LEN {
            debug_assert_eq!(self.chunk_state.len(), 0, "no partial chunk data");
            debug_assert_eq!(CHUNK_LEN.count_ones(), 1, "power of 2 chunk len");
            let mut subtree_len = largest_power_of_two_leq(input.len());
            let count_so_far = self.chunk_state.chunk_counter * CHUNK_LEN as u64;

            while (subtree_len - 1) as u64 & count_so_far != 0 {
                subtree_len /= 2;
            }

            let subtree_chunks = (subtree_len / CHUNK_LEN) as u64;
            if subtree_len <= CHUNK_LEN {
                debug_assert_eq!(subtree_len, CHUNK_LEN);
                self.push_cv(
                    &ChunkState::new(
                        &self.key,
                        self.chunk_state.chunk_counter,
                        self.chunk_state.flags,
                    )
                    .update(&input[..subtree_len])
                    .output()
                    .chaining_value(),
                    self.chunk_state.chunk_counter,
                );
            } else {
                let cv_pair = compress_subtree_to_parent_node::<J>(
                    &input[..subtree_len],
                    &self.key,
                    self.chunk_state.chunk_counter,
                    self.chunk_state.flags,
                );
                let left_cv = array_ref!(cv_pair, 0, 32);
                let right_cv = array_ref!(cv_pair, 32, 32);

                self.push_cv(left_cv, self.chunk_state.chunk_counter);
                self.push_cv(
                    right_cv,
                    self.chunk_state.chunk_counter + (subtree_chunks / 2),
                );
            }
            self.chunk_state.chunk_counter += subtree_chunks;
            input = &input[subtree_len..];
        }

        debug_assert!(input.len() <= CHUNK_LEN);
        if !input.is_empty() {
            self.chunk_state.update(input);

            self.merge_cv_stack(self.chunk_state.chunk_counter);
        }

        self
    }

    fn final_output(&self) -> Output {
        if self.cv_stack.is_empty() {
            debug_assert_eq!(self.chunk_state.chunk_counter, 0);
            return self.chunk_state.output();
        }

        let mut output: Output;
        let mut num_cvs_remaining = self.cv_stack.len();
        if self.chunk_state.len() > 0 {
            debug_assert_eq!(
                self.cv_stack.len(),
                self.chunk_state.chunk_counter.count_ones() as usize,
                "cv stack does not need a merge"
            );
            output = self.chunk_state.output();
        } else {
            debug_assert!(self.cv_stack.len() >= 2);
            output = parent_node_output(
                &self.cv_stack[num_cvs_remaining - 2],
                &self.cv_stack[num_cvs_remaining - 1],
                &self.key,
                self.chunk_state.flags,
            );
            num_cvs_remaining -= 2;
        }
        while num_cvs_remaining > 0 {
            output = parent_node_output(
                &self.cv_stack[num_cvs_remaining - 1],
                &output.chaining_value(),
                &self.key,
                self.chunk_state.flags,
            );
            num_cvs_remaining -= 1;
        }
        output
    }

    pub fn finalize(&self) -> Hash {
        self.final_output().root_hash()
    }

    pub fn finalize_xof(&self) -> OutputReader {
        OutputReader::new(self.final_output())
    }

    pub fn count(&self) -> u64 {
        self.chunk_state.chunk_counter * CHUNK_LEN as u64 + self.chunk_state.len() as u64
    }
}

impl fmt::Debug for Hasher {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Hasher")
            .field("flags", &self.chunk_state.flags)
            .finish()
    }
}

impl Default for Hasher {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl std::io::Write for Hasher {
    #[inline]
    fn write(&mut self, input: &[u8]) -> std::io::Result<usize> {
        self.update(input);
        Ok(input.len())
    }

    #[inline]
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[derive(Clone)]
pub struct OutputReader {
    inner: Output,
    position_within_block: u8,
}

impl OutputReader {
    fn new(inner: Output) -> Self {
        Self {
            inner,
            position_within_block: 0,
        }
    }

    pub fn fill(&mut self, mut buf: &mut [u8]) {
        while !buf.is_empty() {
            let block: [u8; BLOCK_LEN] = self.inner.root_output_block();
            let output_bytes = &block[self.position_within_block as usize..];
            let take = cmp::min(buf.len(), output_bytes.len());
            buf[..take].copy_from_slice(&output_bytes[..take]);
            buf = &mut buf[take..];
            self.position_within_block += take as u8;
            if self.position_within_block == BLOCK_LEN as u8 {
                self.inner.counter += 1;
                self.position_within_block = 0;
            }
        }
    }

    pub fn position(&self) -> u64 {
        self.inner.counter * BLOCK_LEN as u64 + self.position_within_block as u64
    }

    pub fn set_position(&mut self, position: u64) {
        self.position_within_block = (position % BLOCK_LEN as u64) as u8;
        self.inner.counter = position / BLOCK_LEN as u64;
    }
}

impl fmt::Debug for OutputReader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("OutputReader")
            .field("position", &self.position())
            .finish()
    }
}

impl std::io::Read for OutputReader {
    #[inline]
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.fill(buf);
        Ok(buf.len())
    }
}

impl std::io::Seek for OutputReader {
    fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
        let max_position = u64::max_value() as i128;
        let target_position: i128 = match pos {
            std::io::SeekFrom::Start(x) => x as i128,
            std::io::SeekFrom::Current(x) => self.position() as i128 + x as i128,
            std::io::SeekFrom::End(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "seek from end not supported",
                ));
            }
        };
        if target_position < 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "seek before start",
            ));
        }
        self.set_position(cmp::min(target_position, max_position) as u64);
        Ok(self.position())
    }
}