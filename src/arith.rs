use std::simd::{i32x8, i64x4, simd_swizzle, u32x8, Simd};

use crate::{array_mut_ref, CVWords, BLOCK_LEN, IV, MSG_SCHEDULE, OUT_LEN};
pub const DEGREE: usize = 8;

#[inline(always)]
fn round(v: &mut [i32x8; 16], m: &[i32x8; 16], r: usize) {
    v[0] = {
        let i = v[0];
        let j = m[MSG_SCHEDULE[r][0] as usize];
        i + j
    };
    v[1] = {
        let i = v[1];
        let j = m[MSG_SCHEDULE[r][2] as usize];
        i + j
    };
    v[2] = {
        let i = v[2];
        let j = m[MSG_SCHEDULE[r][4] as usize];
        i + j
    };
    v[3] = {
        let i = v[3];
        let j = m[MSG_SCHEDULE[r][6] as usize];
        i + j
    };
    v[0] = {
        let i = v[0];
        let j = v[4];
        i + j
    };
    v[1] = {
        let i = v[1];
        let j = v[5];
        i + j
    };
    v[2] = {
        let i = v[2];
        let j = v[6];
        i + j
    };
    v[3] = {
        let i = v[3];
        let j = v[7];
        i + j
    };
    v[12] = {
        let i = v[12];
        let j = v[0];
        i ^ j
    };
    v[13] = {
        let i = v[13];
        let j = v[1];
        i ^ j
    };
    v[14] = {
        let i = v[14];
        let j = v[2];
        i ^ j
    };
    v[15] = {
        let i = v[15];
        let j = v[3];
        i ^ j
    };
    v[12] = {
        let i = v[12];
        let i: u32x8 = unsafe { std::mem::transmute(i) };
        let i = i >> Simd::from([16; 8]) | i << Simd::from([(32 - 16); 8]);
        unsafe { std::mem::transmute(i) }
    };
    v[13] = {
        let i = v[13];
        let i: u32x8 = unsafe { std::mem::transmute(i) };
        let i = i >> Simd::from([16; 8]) | i << Simd::from([(32 - 16); 8]);
        unsafe { std::mem::transmute(i) }
    };
    v[14] = {
        let i = v[14];
        let i: u32x8 = unsafe { std::mem::transmute(i) };
        let i = i >> Simd::from([16; 8]) | i << Simd::from([(32 - 16); 8]);
        unsafe { std::mem::transmute(i) }
    };
    v[15] = {
        let i = v[15];
        let i: u32x8 = unsafe { std::mem::transmute(i) };
        let i = i >> Simd::from([16; 8]) | i << Simd::from([(32 - 16); 8]);
        unsafe { std::mem::transmute(i) }
    };
    v[8] = {
        let i = v[8];
        let j = v[12];
        i + j
    };
    v[9] = {
        let i = v[9];
        let j = v[13];
        i + j
    };
    v[10] = {
        let i = v[10];
        let j = v[14];
        i + j
    };
    v[11] = {
        let i = v[11];
        let j = v[15];
        i + j
    };
    v[4] = {
        let i = v[4];
        let j = v[8];
        i ^ j
    };
    v[5] = {
        let i = v[5];
        let j = v[9];
        i ^ j
    };
    v[6] = {
        let i = v[6];
        let j = v[10];
        i ^ j
    };
    v[7] = {
        let i = v[7];
        let j = v[11];
        i ^ j
    };
    v[4] = {
        let i = v[4];
        let i: u32x8 = unsafe { std::mem::transmute(i) };
        let i = i >> Simd::from([12; 8]) | i << Simd::from([(32 - 12); 8]);
        unsafe { std::mem::transmute(i) }
    };
    v[5] = {
        let i = v[5];
        let i: u32x8 = unsafe { std::mem::transmute(i) };
        let i = i >> Simd::from([12; 8]) | i << Simd::from([(32 - 12); 8]);
        unsafe { std::mem::transmute(i) }
    };
    v[6] = {
        let i = v[6];
        let i: u32x8 = unsafe { std::mem::transmute(i) };
        let i = i >> Simd::from([12; 8]) | i << Simd::from([(32 - 12); 8]);
        unsafe { std::mem::transmute(i) }
    };
    v[7] = {
        let i = v[7];
        let i: u32x8 = unsafe { std::mem::transmute(i) };
        let i = i >> Simd::from([12; 8]) | i << Simd::from([(32 - 12); 8]);
        unsafe { std::mem::transmute(i) }
    };
    v[0] = {
        let i = v[0];
        let j = m[MSG_SCHEDULE[r][1] as usize];
        i + j
    };
    v[1] = {
        let i = v[1];
        let j = m[MSG_SCHEDULE[r][3] as usize];
        i + j
    };
    v[2] = {
        let i = v[2];
        let j = m[MSG_SCHEDULE[r][5] as usize];
        i + j
    };
    v[3] = {
        let i = v[3];
        let j = m[MSG_SCHEDULE[r][7] as usize];
        i + j
    };
    v[0] = {
        let i = v[0];
        let j = v[4];
        i + j
    };
    v[1] = {
        let i = v[1];
        let j = v[5];
        i + j
    };
    v[2] = {
        let i = v[2];
        let j = v[6];
        i + j
    };
    v[3] = {
        let i = v[3];
        let j = v[7];
        i + j
    };
    v[12] = {
        let i = v[12];
        let j = v[0];
        i ^ j
    };
    v[13] = {
        let i = v[13];
        let j = v[1];
        i ^ j
    };
    v[14] = {
        let i = v[14];
        let j = v[2];
        i ^ j
    };
    v[15] = {
        let i = v[15];
        let j = v[3];
        i ^ j
    };
    v[12] = {
        let i = v[12];
        let i: u32x8 = unsafe { std::mem::transmute(i) };
        let i = i >> Simd::from([8; 8]) | i << Simd::from([(32 - 8); 8]);
        unsafe { std::mem::transmute(i) }
    };
    v[13] = {
        let i = v[13];
        let i: u32x8 = unsafe { std::mem::transmute(i) };
        let i = i >> Simd::from([8; 8]) | i << Simd::from([(32 - 8); 8]);
        unsafe { std::mem::transmute(i) }
    };
    v[14] = {
        let i = v[14];
        let i: u32x8 = unsafe { std::mem::transmute(i) };
        let i = i >> Simd::from([8; 8]) | i << Simd::from([(32 - 8); 8]);
        unsafe { std::mem::transmute(i) }
    };
    v[15] = {
        let i = v[15];
        let i: u32x8 = unsafe { std::mem::transmute(i) };
        let i = i >> Simd::from([8; 8]) | i << Simd::from([(32 - 8); 8]);
        unsafe { std::mem::transmute(i) }
    };
    v[8] = {
        let i = v[8];
        let j = v[12];
        i + j
    };
    v[9] = {
        let i = v[9];
        let j = v[13];
        i + j
    };
    v[10] = {
        let i = v[10];
        let j = v[14];
        i + j
    };
    v[11] = {
        let i = v[11];
        let j = v[15];
        i + j
    };
    v[4] = {
        let i = v[4];
        let j = v[8];
        i ^ j
    };
    v[5] = {
        let i = v[5];
        let j = v[9];
        i ^ j
    };
    v[6] = {
        let i = v[6];
        let j = v[10];
        i ^ j
    };
    v[7] = {
        let i = v[7];
        let j = v[11];
        i ^ j
    };
    v[4] = {
        let i = v[4];
        let i: u32x8 = unsafe { std::mem::transmute(i) };
        let i = i >> Simd::from([7; 8]) | i << Simd::from([(32 - 7); 8]);
        unsafe { std::mem::transmute(i) }
    };
    v[5] = {
        let i = v[5];
        let i: u32x8 = unsafe { std::mem::transmute(i) };
        let i = i >> Simd::from([7; 8]) | i << Simd::from([(32 - 7); 8]);
        unsafe { std::mem::transmute(i) }
    };
    v[6] = {
        let i = v[6];
        let i: u32x8 = unsafe { std::mem::transmute(i) };
        let i = i >> Simd::from([7; 8]) | i << Simd::from([(32 - 7); 8]);
        unsafe { std::mem::transmute(i) }
    };
    v[7] = {
        let i = v[7];
        let i: u32x8 = unsafe { std::mem::transmute(i) };
        let i = i >> Simd::from([7; 8]) | i << Simd::from([(32 - 7); 8]);
        unsafe { std::mem::transmute(i) }
    };

    v[0] = {
        let i = v[0];
        let j = m[MSG_SCHEDULE[r][8] as usize];
        i + j
    };
    v[1] = {
        let i = v[1];
        let j = m[MSG_SCHEDULE[r][10] as usize];
        i + j
    };
    v[2] = {
        let i = v[2];
        let j = m[MSG_SCHEDULE[r][12] as usize];
        i + j
    };
    v[3] = {
        let i = v[3];
        let j = m[MSG_SCHEDULE[r][14] as usize];
        i + j
    };
    v[0] = {
        let i = v[0];
        let j = v[5];
        i + j
    };
    v[1] = {
        let i = v[1];
        let j = v[6];
        i + j
    };
    v[2] = {
        let i = v[2];
        let j = v[7];
        i + j
    };
    v[3] = {
        let i = v[3];
        let j = v[4];
        i + j
    };
    v[15] = {
        let i = v[15];
        let j = v[0];
        i ^ j
    };
    v[12] = {
        let i = v[12];
        let j = v[1];
        i ^ j
    };
    v[13] = {
        let i = v[13];
        let j = v[2];
        i ^ j
    };
    v[14] = {
        let i = v[14];
        let j = v[3];
        i ^ j
    };
    v[15] = {
        let i = v[15];
        let i: u32x8 = unsafe { std::mem::transmute(i) };
        let i = i >> Simd::from([16; 8]) | i << Simd::from([(32 - 16); 8]);
        unsafe { std::mem::transmute(i) }
    };
    v[12] = {
        let i = v[12];
        let i: u32x8 = unsafe { std::mem::transmute(i) };
        let i = i >> Simd::from([16; 8]) | i << Simd::from([(32 - 16); 8]);
        unsafe { std::mem::transmute(i) }
    };
    v[13] = {
        let i = v[13];
        let i: u32x8 = unsafe { std::mem::transmute(i) };
        let i = i >> Simd::from([16; 8]) | i << Simd::from([(32 - 16); 8]);
        unsafe { std::mem::transmute(i) }
    };
    v[14] = {
        let i = v[14];
        let i: u32x8 = unsafe { std::mem::transmute(i) };
        let i = i >> Simd::from([16; 8]) | i << Simd::from([(32 - 16); 8]);
        unsafe { std::mem::transmute(i) }
    };
    v[10] = {
        let i = v[10];
        let j = v[15];
        i + j
    };
    v[11] = {
        let i = v[11];
        let j = v[12];
        i + j
    };
    v[8] = {
        let i = v[8];
        let j = v[13];
        i + j
    };
    v[9] = {
        let i = v[9];
        let j = v[14];
        i + j
    };
    v[5] = {
        let i = v[5];
        let j = v[10];
        i ^ j
    };
    v[6] = {
        let i = v[6];
        let j = v[11];
        i ^ j
    };
    v[7] = {
        let i = v[7];
        let j = v[8];
        i ^ j
    };
    v[4] = {
        let i = v[4];
        let j = v[9];
        i ^ j
    };
    v[5] = {
        let i = v[5];
        let i: u32x8 = unsafe { std::mem::transmute(i) };
        let i = i >> Simd::from([12; 8]) | i << Simd::from([(32 - 12); 8]);
        unsafe { std::mem::transmute(i) }
    };
    v[6] = {
        let i = v[6];
        let i: u32x8 = unsafe { std::mem::transmute(i) };
        let i = i >> Simd::from([12; 8]) | i << Simd::from([(32 - 12); 8]);
        unsafe { std::mem::transmute(i) }
    };
    v[7] = {
        let i = v[7];
        let i: u32x8 = unsafe { std::mem::transmute(i) };
        let i = i >> Simd::from([12; 8]) | i << Simd::from([(32 - 12); 8]);
        unsafe { std::mem::transmute(i) }
    };
    v[4] = {
        let i = v[4];
        let i: u32x8 = unsafe { std::mem::transmute(i) };
        let i = i >> Simd::from([12; 8]) | i << Simd::from([(32 - 12); 8]);
        unsafe { std::mem::transmute(i) }
    };
    v[0] = {
        let i = v[0];
        let j = m[MSG_SCHEDULE[r][9] as usize];
        i + j
    };
    v[1] = {
        let i = v[1];
        let j = m[MSG_SCHEDULE[r][11] as usize];
        i + j
    };
    v[2] = {
        let i = v[2];
        let j = m[MSG_SCHEDULE[r][13] as usize];
        i + j
    };
    v[3] = {
        let i = v[3];
        let j = m[MSG_SCHEDULE[r][15] as usize];
        i + j
    };
    v[0] = {
        let i = v[0];
        let j = v[5];
        i + j
    };
    v[1] = {
        let i = v[1];
        let j = v[6];
        i + j
    };
    v[2] = {
        let i = v[2];
        let j = v[7];
        i + j
    };
    v[3] = {
        let i = v[3];
        let j = v[4];
        i + j
    };
    v[15] = {
        let i = v[15];
        let j = v[0];
        i ^ j
    };
    v[12] = {
        let i = v[12];
        let j = v[1];
        i ^ j
    };
    v[13] = {
        let i = v[13];
        let j = v[2];
        i ^ j
    };
    v[14] = {
        let i = v[14];
        let j = v[3];
        i ^ j
    };
    v[15] = {
        let i = v[15];
        let i: u32x8 = unsafe { std::mem::transmute(i) };
        let i = i >> Simd::from([8; 8]) | i << Simd::from([(32 - 8); 8]);
        unsafe { std::mem::transmute(i) }
    };
    v[12] = {
        let i = v[12];
        let i: u32x8 = unsafe { std::mem::transmute(i) };
        let i = i >> Simd::from([8; 8]) | i << Simd::from([(32 - 8); 8]);
        unsafe { std::mem::transmute(i) }
    };
    v[13] = {
        let i = v[13];
        let i: u32x8 = unsafe { std::mem::transmute(i) };
        let i = i >> Simd::from([8; 8]) | i << Simd::from([(32 - 8); 8]);
        unsafe { std::mem::transmute(i) }
    };
    v[14] = {
        let i = v[14];
        let i: u32x8 = unsafe { std::mem::transmute(i) };
        let i = i >> Simd::from([8; 8]) | i << Simd::from([(32 - 8); 8]);
        unsafe { std::mem::transmute(i) }
    };
    v[10] = {
        let i = v[10];
        let j = v[15];
        i + j
    };
    v[11] = {
        let i = v[11];
        let j = v[12];
        i + j
    };
    v[8] = {
        let i = v[8];
        let j = v[13];
        i + j
    };
    v[9] = {
        let i = v[9];
        let j = v[14];
        i + j
    };
    v[5] = {
        let i = v[5];
        let j = v[10];
        i ^ j
    };
    v[6] = {
        let i = v[6];
        let j = v[11];
        i ^ j
    };
    v[7] = {
        let i = v[7];
        let j = v[8];
        i ^ j
    };
    v[4] = {
        let i = v[4];
        let j = v[9];
        i ^ j
    };
    v[5] = {
        let i = v[5];
        let i: u32x8 = unsafe { std::mem::transmute(i) };
        let i = i >> Simd::from([7; 8]) | i << Simd::from([(32 - 7); 8]);
        unsafe { std::mem::transmute(i) }
    };
    v[6] = {
        let i = v[6];
        let i: u32x8 = unsafe { std::mem::transmute(i) };
        let i = i >> Simd::from([7; 8]) | i << Simd::from([(32 - 7); 8]);
        unsafe { std::mem::transmute(i) }
    };
    v[7] = {
        let i = v[7];
        let i: u32x8 = unsafe { std::mem::transmute(i) };
        let i = i >> Simd::from([7; 8]) | i << Simd::from([(32 - 7); 8]);
        unsafe { std::mem::transmute(i) }
    };
    v[4] = {
        let i = v[4];
        let i: u32x8 = unsafe { std::mem::transmute(i) };
        let i = i >> Simd::from([7; 8]) | i << Simd::from([(32 - 7); 8]);
        unsafe { std::mem::transmute(i) }
    };
}

macro_rules! unpack8lo {
    ($x:expr,$y:expr) => {
        simd_swizzle!($x, $y, [0, 8 + 0, 1, 8 + 1, 4, 8 + 4, 5, 8 + 5])
    };
}
macro_rules! unpack8hi {
    ($x:expr,$y:expr) => {
        simd_swizzle!($x, $y, [2, 8 + 2, 3, 8 + 3, 6, 8 + 6, 7, 8 + 7])
    };
}
macro_rules! unpack8 {
    ($x:expr,$y:expr) => {
        (unpack8lo!($x, $y), unpack8hi!($x, $y))
    };
}

macro_rules! unpack4lo {
    ($x:expr,$y:expr) => {
        simd_swizzle!($x, $y, [0, 4 + 0, 2, 4 + 2])
    };
}
macro_rules! unpack4hi {
    ($x:expr,$y:expr) => {
        simd_swizzle!($x, $y, [1, 4 + 1, 3, 4 + 3])
    };
}
macro_rules! unpack4 {
    ($x:expr,$y:expr) => {
        (unpack4lo!($x, $y), unpack4hi!($x, $y))
    };
}
macro_rules! unpack2lo {
    ($x:expr,$y:expr) => {
        simd_swizzle!($x, $y, [0, 1, 4 + 0, 4 + 1])
    };
}
macro_rules! unpack2hi {
    ($x:expr,$y:expr) => {
        simd_swizzle!($x, $y, [2, 3, 4 + 2, 4 + 3])
    };
}
macro_rules! unpack2 {
    ($x:expr,$y:expr) => {
        (unpack2lo!($x, $y), unpack2hi!($x, $y))
    };
}

fn transpose_vecs(v32: &mut [i32x8]) {
    unsafe {
        let (v64_0, v64_1) =
            std::mem::transmute::<(i32x8, i32x8), (i64x4, i64x4)>(unpack8!(v32[0], v32[0 + 1]));

        let (v64_2, v64_3) =
            std::mem::transmute::<(i32x8, i32x8), (i64x4, i64x4)>(unpack8!(v32[2], v32[2 + 1]));

        let (v64_4, v64_5) =
            std::mem::transmute::<(i32x8, i32x8), (i64x4, i64x4)>(unpack8!(v32[4], v32[4 + 1]));

        let (v64_6, v64_7) =
            std::mem::transmute::<(i32x8, i32x8), (i64x4, i64x4)>(unpack8!(v32[6], v32[6 + 1]));

        let (v64_0, v64_2, v64_1, v64_3) = {
            let (a, b) = unpack4!(v64_0, v64_2);
            let (c, d) = unpack4!(v64_1, v64_3);
            (a, b, c, d)
        };
        let (v64_4, v64_6, v64_5, v64_7) = {
            let (a, b) = unpack4!(v64_4, v64_6);
            let (c, d) = unpack4!(v64_5, v64_7);
            (a, b, c, d)
        };

        let v128 = {
            let ptr = (&mut v32[0..]).as_mut_ptr() as *mut i64x4;
            std::slice::from_raw_parts_mut(ptr, 8)
        };
        (v128[0], v128[0 + 4]) = unpack2!(v64_0, v64_4);
        (v128[1], v128[1 + 4]) = unpack2!(v64_2, v64_6);
        (v128[2], v128[2 + 4]) = unpack2!(v64_1, v64_5);
        (v128[3], v128[3 + 4]) = unpack2!(v64_3, v64_7);
    }
}

#[test]
fn test_tr() {
    let mut arr: Box<[i32]> = (0..64).collect::<Box<[i32]>>();
    let ptr = unsafe { std::slice::from_raw_parts_mut(arr.as_mut_ptr() as *mut i32x8, 8) };
    transpose_vecs(ptr);
    for i in (0..64).step_by(8) {
        println!("{:?}", &arr[i..i + 8]);
    }
}

fn transpose_msg_vecs(inputs: &[*const u8; DEGREE], block_offset: usize) -> [i32x8; 16] {
    let mut vecs = unsafe {
        [
            {
                let arr = inputs[0].add(block_offset + 0 * 4 * DEGREE);
                i32x8::from_slice(std::slice::from_raw_parts(arr as *mut _, 8))
            },
            {
                let arr = inputs[1].add(block_offset + 0 * 4 * DEGREE);
                i32x8::from_slice(std::slice::from_raw_parts(arr as *mut _, 8))
            },
            {
                let arr = inputs[2].add(block_offset + 0 * 4 * DEGREE);
                i32x8::from_slice(std::slice::from_raw_parts(arr as *mut _, 8))
            },
            {
                let arr = inputs[3].add(block_offset + 0 * 4 * DEGREE);
                i32x8::from_slice(std::slice::from_raw_parts(arr as *mut _, 8))
            },
            {
                let arr = inputs[4].add(block_offset + 0 * 4 * DEGREE);
                i32x8::from_slice(std::slice::from_raw_parts(arr as *mut _, 8))
            },
            {
                let arr = inputs[5].add(block_offset + 0 * 4 * DEGREE);
                i32x8::from_slice(std::slice::from_raw_parts(arr as *mut _, 8))
            },
            {
                let arr = inputs[6].add(block_offset + 0 * 4 * DEGREE);
                i32x8::from_slice(std::slice::from_raw_parts(arr as *mut _, 8))
            },
            {
                let arr = inputs[7].add(block_offset + 0 * 4 * DEGREE);
                i32x8::from_slice(std::slice::from_raw_parts(arr as *mut _, 8))
            },
            {
                let arr = inputs[0].add(block_offset + 1 * 4 * DEGREE);
                i32x8::from_slice(std::slice::from_raw_parts(arr as *mut _, 8))
            },
            {
                let arr = inputs[1].add(block_offset + 1 * 4 * DEGREE);
                i32x8::from_slice(std::slice::from_raw_parts(arr as *mut _, 8))
            },
            {
                let arr = inputs[2].add(block_offset + 1 * 4 * DEGREE);
                i32x8::from_slice(std::slice::from_raw_parts(arr as *mut _, 8))
            },
            {
                let arr = inputs[3].add(block_offset + 1 * 4 * DEGREE);
                i32x8::from_slice(std::slice::from_raw_parts(arr as *mut _, 8))
            },
            {
                let arr = inputs[4].add(block_offset + 1 * 4 * DEGREE);
                i32x8::from_slice(std::slice::from_raw_parts(arr as *mut _, 8))
            },
            {
                let arr = inputs[5].add(block_offset + 1 * 4 * DEGREE);
                i32x8::from_slice(std::slice::from_raw_parts(arr as *mut _, 8))
            },
            {
                let arr = inputs[6].add(block_offset + 1 * 4 * DEGREE);
                i32x8::from_slice(std::slice::from_raw_parts(arr as *mut _, 8))
            },
            {
                let arr = inputs[7].add(block_offset + 1 * 4 * DEGREE);
                i32x8::from_slice(std::slice::from_raw_parts(arr as *mut _, 8))
            },
        ]
    };
    transpose_vecs(&mut vecs[0..8]);
    transpose_vecs(&mut vecs[8..16]);
    vecs
}

#[inline(always)]
fn load_counters(counter: u64, increment_counter: bool) -> (i32x8, i32x8) {
    let mask = if increment_counter { !0 } else { 0 };
    (
        i32x8::from_array([
            {
                let counter = counter + (mask & 0);
                counter as u32
            } as i32,
            {
                let counter = counter + (mask & 1);
                counter as u32
            } as i32,
            {
                let counter = counter + (mask & 2);
                counter as u32
            } as i32,
            {
                let counter = counter + (mask & 3);
                counter as u32
            } as i32,
            {
                let counter = counter + (mask & 4);
                counter as u32
            } as i32,
            {
                let counter = counter + (mask & 5);
                counter as u32
            } as i32,
            {
                let counter = counter + (mask & 6);
                counter as u32
            } as i32,
            {
                let counter = counter + (mask & 7);
                counter as u32
            } as i32,
        ]),
        i32x8::from_array([
            {
                let counter = counter + (mask & 0);
                (counter >> 32) as u32
            } as i32,
            {
                let counter = counter + (mask & 1);
                (counter >> 32) as u32
            } as i32,
            {
                let counter = counter + (mask & 2);
                (counter >> 32) as u32
            } as i32,
            {
                let counter = counter + (mask & 3);
                (counter >> 32) as u32
            } as i32,
            {
                let counter = counter + (mask & 4);
                (counter >> 32) as u32
            } as i32,
            {
                let counter = counter + (mask & 5);
                (counter >> 32) as u32
            } as i32,
            {
                let counter = counter + (mask & 6);
                (counter >> 32) as u32
            } as i32,
            {
                let counter = counter + (mask & 7);
                (counter >> 32) as u32
            } as i32,
        ]),
    )
}

pub fn hash8(
    inputs: &[*const u8; DEGREE],
    blocks: usize,
    key: &CVWords,
    counter: u64,
    increment_counter: bool,
    flags: u8,
    flags_start: u8,
    flags_end: u8,
    out: &mut [u8; DEGREE * OUT_LEN],
) {
    fn set1(x: i32) -> i32x8 {
        i32x8::from_array([x; 8])
    }
    let mut h_vecs = [
        set1(key[0] as i32),
        set1(key[1] as i32),
        set1(key[2] as i32),
        set1(key[3] as i32),
        set1(key[4] as i32),
        set1(key[5] as i32),
        set1(key[6] as i32),
        set1(key[7] as i32),
    ];
    let (counter_low_vec, counter_high_vec) = load_counters(counter, increment_counter);
    let mut block_flags = flags | flags_start;

    for block in 0..blocks {
        if block + 1 == blocks {
            block_flags |= flags_end;
        }
        let block_len_vec = set1(BLOCK_LEN as i32);
        let block_flags_vec = set1(block_flags as i32);
        let msg_vecs = transpose_msg_vecs(inputs, block * BLOCK_LEN);

        let v = [
            h_vecs[0],
            h_vecs[1],
            h_vecs[2],
            h_vecs[3],
            h_vecs[4],
            h_vecs[5],
            h_vecs[6],
            h_vecs[7],
            set1(IV[0] as i32),
            set1(IV[1] as i32),
            set1(IV[2] as i32),
            set1(IV[3] as i32),
            counter_low_vec,
            counter_high_vec,
            block_len_vec,
            block_flags_vec,
        ];
        let mut v = v.map(|x| unsafe { std::mem::transmute(x) });
        let msg_vecs = msg_vecs.map(|x| unsafe { std::mem::transmute(x) });
        round(&mut v, &msg_vecs, 0);
        round(&mut v, &msg_vecs, 1);
        round(&mut v, &msg_vecs, 2);
        round(&mut v, &msg_vecs, 3);
        round(&mut v, &msg_vecs, 4);
        round(&mut v, &msg_vecs, 5);
        round(&mut v, &msg_vecs, 6);
        unsafe {
            h_vecs[0] = std::mem::transmute(v[0] ^ v[8]);
            h_vecs[1] = std::mem::transmute(v[1] ^ v[9]);
            h_vecs[2] = std::mem::transmute(v[2] ^ v[10]);
            h_vecs[3] = std::mem::transmute(v[3] ^ v[11]);
            h_vecs[4] = std::mem::transmute(v[4] ^ v[12]);
            h_vecs[5] = std::mem::transmute(v[5] ^ v[13]);
            h_vecs[6] = std::mem::transmute(v[6] ^ v[14]);
            h_vecs[7] = std::mem::transmute(v[7] ^ v[15]);
        }
        block_flags = flags;
    }

    transpose_vecs(&mut h_vecs);
    unsafe {
        std::ptr::write(
            out.as_mut_ptr().add(0 * 4 * DEGREE) as *mut i32x8,
            h_vecs[0],
        );
        std::ptr::write(
            out.as_mut_ptr().add(1 * 4 * DEGREE) as *mut i32x8,
            h_vecs[1],
        );
        std::ptr::write(
            out.as_mut_ptr().add(2 * 4 * DEGREE) as *mut i32x8,
            h_vecs[2],
        );
        std::ptr::write(
            out.as_mut_ptr().add(3 * 4 * DEGREE) as *mut i32x8,
            h_vecs[3],
        );
        std::ptr::write(
            out.as_mut_ptr().add(4 * 4 * DEGREE) as *mut i32x8,
            h_vecs[4],
        );
        std::ptr::write(
            out.as_mut_ptr().add(5 * 4 * DEGREE) as *mut i32x8,
            h_vecs[5],
        );
        std::ptr::write(
            out.as_mut_ptr().add(6 * 4 * DEGREE) as *mut i32x8,
            h_vecs[6],
        );
        std::ptr::write(
            out.as_mut_ptr().add(7 * 4 * DEGREE) as *mut i32x8,
            h_vecs[7],
        );
    }
}

pub fn hash_many<const N: usize>(
    mut inputs: &[&[u8; N]],
    key: &CVWords,
    mut counter: u64,
    increment_counter: bool,
    flags: u8,
    flags_start: u8,
    flags_end: u8,
    mut out: &mut [u8],
) {
    debug_assert!(out.len() >= inputs.len() * OUT_LEN, "out too short");
    while inputs.len() >= DEGREE && out.len() >= DEGREE * OUT_LEN {
        let input_ptrs: &[*const u8; DEGREE] =
            unsafe { &*(inputs.as_ptr() as *const [*const u8; DEGREE]) };
        let blocks = N / BLOCK_LEN;
        hash8(
            input_ptrs,
            blocks,
            key,
            counter,
            increment_counter,
            flags,
            flags_start,
            flags_end,
            array_mut_ref!(out, 0, DEGREE * OUT_LEN),
        );
        if increment_counter {
            counter += DEGREE as u64;
        }
        inputs = &inputs[DEGREE..];
        out = &mut out[DEGREE * OUT_LEN..];
    }
    crate::fallback::hash_many(
        inputs,
        key,
        counter,
        increment_counter,
        flags,
        flags_start,
        flags_end,
        out,
    );
}

#[test]
fn test_hash_many() {
    crate::test::test_hash_many_fn(hash_many, hash_many);
}
