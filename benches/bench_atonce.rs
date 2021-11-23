use blake2::Digest;
use criterion::{Criterion, Fun};
use rand::{prelude::SliceRandom, RngCore};
const KIB: usize = 1024;

// This struct randomizes two things:
// 1. The actual bytes of input.
// 2. The page offset the input starts at.
pub struct RandomInput {
    buf: Vec<u8>,
    len: usize,
    offsets: Vec<usize>,
    offset_index: usize,
}

impl RandomInput {
    pub fn new(len: usize) -> Self {
        let page_size: usize = 4096;
        let mut buf = vec![0u8; len + page_size];
        let mut rng = rand::thread_rng();
        rng.fill_bytes(&mut buf);
        let mut offsets: Vec<usize> = (0..page_size).collect();
        offsets.shuffle(&mut rng);
        Self {
            buf,
            len,
            offsets,
            offset_index: 0,
        }
    }

    pub fn get(&mut self) -> &[u8] {
        let offset = self.offsets[self.offset_index];
        self.offset_index += 1;
        if self.offset_index >= self.offsets.len() {
            self.offset_index = 0;
        }
        &self.buf[offset..][..self.len]
    }
}

fn bench_atonce(c: &mut Criterion, len: usize) {
    let mut data = RandomInput::new(len);
    let data = data.get();
    let mut group = c.benchmark_group(format!("bench atonce with size {:?}", len));

    group.bench_function("MD5", |b| b.iter(|| md5::compute(data)));
    group.bench_function("SHA256", |b| b.iter(|| sha2::Sha256::digest(data)));
    group.bench_function("SHA384", |b| b.iter(|| sha2::Sha384::digest(data)));
    group.bench_function("SHA512", |b| b.iter(|| sha2::Sha512::digest(data)));
    group.bench_function("BLAKE2B", |b| b.iter(|| blake2::Blake2b::digest(data)));
    group.bench_function("BLAKE2S", |b| b.iter(|| blake2::Blake2s::digest(data)));
    group.bench_function("BLAKE3_STD", |b| b.iter(|| blake3_std::hash(data)));
    group.finish()
}

fn bench_atonce_0001_block(c: &mut Criterion) {
    bench_atonce(c, 64);
}

fn bench_atonce_0001_kib(c: &mut Criterion) {
    bench_atonce(c, 1 * KIB);
}

fn bench_atonce_0002_kib(c: &mut Criterion) {
    bench_atonce(c, 2 * KIB);
}

fn bench_atonce_0004_kib(c: &mut Criterion) {
    bench_atonce(c, 4 * KIB);
}

fn bench_atonce_0008_kib(c: &mut Criterion) {
    bench_atonce(c, 8 * KIB);
}

fn bench_atonce_0016_kib(c: &mut Criterion) {
    bench_atonce(c, 16 * KIB);
}

fn bench_atonce_0032_kib(c: &mut Criterion) {
    bench_atonce(c, 32 * KIB);
}

fn bench_atonce_0064_kib(c: &mut Criterion) {
    bench_atonce(c, 64 * KIB);
}

fn bench_atonce_0128_kib(c: &mut Criterion) {
    bench_atonce(c, 128 * KIB);
}

fn bench_atonce_0256_kib(c: &mut Criterion) {
    bench_atonce(c, 256 * KIB);
}

fn bench_atonce_0512_kib(c: &mut Criterion) {
    bench_atonce(c, 512 * KIB);
}

fn bench_atonce_1024_kib(c: &mut Criterion) {
    bench_atonce(c, 1024 * KIB);
}

fn bench_atonce_2048_kib(c: &mut Criterion) {
    bench_atonce(c, 1024 * KIB);
}

fn bench_atonce_4096_kib(c: &mut Criterion) {
    bench_atonce(c, 1024 * KIB);
}

criterion::criterion_group!(
    name = hash_at_once;
    config = Criterion::default().sample_size(1000);
    targets =
    bench_atonce_0001_block,
    bench_atonce_0001_kib,
    bench_atonce_0002_kib,
    bench_atonce_0004_kib,
    bench_atonce_0008_kib,
    bench_atonce_0016_kib,
    bench_atonce_0032_kib,
    bench_atonce_0064_kib,
    bench_atonce_0128_kib,
    bench_atonce_0256_kib,
    bench_atonce_0512_kib,
    bench_atonce_1024_kib,
    bench_atonce_2048_kib,
    bench_atonce_4096_kib
);
