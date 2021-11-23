use crate::{CVWords, CHUNK_LEN, OUT_LEN};
use arrayref::array_ref;
use arrayvec::ArrayVec;
use core::usize;

pub const TEST_KEY_WORDS: CVWords = [
    1952540791, 1752440947, 1816469605, 1752394102, 1919907616, 1868963940, 1919295602, 1684956521,
];

pub fn paint_test_input(buf: &mut [u8]) {
    for (i, b) in buf.iter_mut().enumerate() {
        *b = (i % 251) as u8;
    }
}

type HashManyFn<A> = unsafe fn(
    inputs: &[&A],
    key: &CVWords,
    counter: u64,
    increment_counter: bool,
    flags: u8,
    flags_start: u8,
    flags_end: u8,
    out: &mut [u8],
);

pub fn test_hash_many_fn(
    hash_many_chunks_fn: HashManyFn<[u8; CHUNK_LEN]>,
    hash_many_parents_fn: HashManyFn<[u8; 2 * OUT_LEN]>,
) {
    const NUM_INPUTS: usize = 31;
    let mut input_buf = [0; CHUNK_LEN * NUM_INPUTS];
    crate::test::paint_test_input(&mut input_buf);

    let counter = (1u64 << 32) - 1;

    let mut chunks = ArrayVec::<&[u8; CHUNK_LEN], NUM_INPUTS>::new();
    for i in 0..NUM_INPUTS {
        chunks.push(array_ref!(input_buf, i * CHUNK_LEN, CHUNK_LEN));
    }
    let mut portable_chunks_out = [0; NUM_INPUTS * OUT_LEN];
    crate::fallback::hash_many(
        &chunks,
        &TEST_KEY_WORDS,
        counter,
        true,
        crate::KEYED_HASH,
        crate::CHUNK_START,
        crate::CHUNK_END,
        &mut portable_chunks_out,
    );

    let mut test_chunks_out = [0; NUM_INPUTS * OUT_LEN];
    unsafe {
        hash_many_chunks_fn(
            &chunks[..],
            &TEST_KEY_WORDS,
            counter,
            true,
            crate::KEYED_HASH,
            crate::CHUNK_START,
            crate::CHUNK_END,
            &mut test_chunks_out,
        );
    }
    for n in 0..NUM_INPUTS {
        dbg!(n);
        assert_eq!(
            &portable_chunks_out[n * OUT_LEN..][..OUT_LEN],
            &test_chunks_out[n * OUT_LEN..][..OUT_LEN]
        );
    }

    let mut parents = ArrayVec::<&[u8; 2 * OUT_LEN], NUM_INPUTS>::new();
    for i in 0..NUM_INPUTS {
        parents.push(array_ref!(input_buf, i * 2 * OUT_LEN, 2 * OUT_LEN));
    }
    let mut portable_parents_out = [0; NUM_INPUTS * OUT_LEN];
    crate::fallback::hash_many(
        &parents,
        &TEST_KEY_WORDS,
        counter,
        false,
        crate::KEYED_HASH | crate::PARENT,
        0,
        0,
        &mut portable_parents_out,
    );

    let mut test_parents_out = [0; NUM_INPUTS * OUT_LEN];
    unsafe {
        hash_many_parents_fn(
            &parents[..],
            &TEST_KEY_WORDS,
            counter,
            false,
            crate::KEYED_HASH | crate::PARENT,
            0,
            0,
            &mut test_parents_out,
        );
    }
    for n in 0..NUM_INPUTS {
        dbg!(n);
        assert_eq!(
            &portable_parents_out[n * OUT_LEN..][..OUT_LEN],
            &test_parents_out[n * OUT_LEN..][..OUT_LEN]
        );
    }
}

#[test]
fn test_fuzz_hasher() {
    use rand::{Rng, SeedableRng};
    fn reference_hash(input: &[u8]) -> crate::Hash {
        let mut hasher = crate::reference_impl::Hasher::new();
        hasher.update(input);
        let mut bytes = [0; 32];
        hasher.finalize(&mut bytes);
        bytes.into()
    }
    const INPUT_MAX: usize = 4 * CHUNK_LEN;
    let mut input_buf = [0; 3 * INPUT_MAX];
    paint_test_input(&mut input_buf);

    let num_tests = 10_000;

    let mut rng = rand_chacha::ChaCha8Rng::from_seed([1; 32]);
    for _num_test in 0..num_tests {
        dbg!(_num_test);
        let mut hasher = crate::Hasher::new();
        let mut total_input = 0;

        for _ in 0..3 {
            let input_len = rng.gen_range(0..(INPUT_MAX + 1));

            dbg!(input_len);
            let input = &input_buf[total_input..][..input_len];
            hasher.update(input);
            total_input += input_len;
        }
        let expected = reference_hash(&input_buf[..total_input]);
        assert_eq!(expected, hasher.finalize());
    }
}
