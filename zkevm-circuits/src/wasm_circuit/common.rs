use num_traits::checked_pow;
use wabt::wat2wasm;
use wasmbin::io::{DecodeError, Encode};
use wasmbin::Module;
use wasmbin::sections::Kind;
use wasmbin::visit::{Visit, VisitError};
use crate::wasm_circuit::leb128_circuit::helpers::leb128_compute_last_byte_offset;

/// Returns section len and leb bytes count representing section len
pub fn wasm_compute_section_len(wasm_bytes: &[u8], len_start_index: usize) -> Result<(usize, u8), ()> {
    const MAX_LEB_BYTES: usize = 5;
    if len_start_index >= wasm_bytes.len() { return Err(()) }
    let mut section_len: usize = 0;
    let mut i = len_start_index;
    loop {
        let byte = wasm_bytes[i];
        let mut byte_val: u32 = (byte & 0b1111111) as u32;
        byte_val = byte_val * checked_pow(0b10000000, i - len_start_index).unwrap();
        section_len += byte_val as usize;
        if byte & 0b10000000 == 0 { break }
        i += 1;
        if i - len_start_index >= MAX_LEB_BYTES { return Err(()) }
    }
    Ok((section_len, (i - len_start_index + 1) as u8))
}

pub fn wat_extract_section_bytecode(path_to_file: &str, kind: Kind) -> Vec<u8> {
    let wat: Vec<u8> = std::fs::read(path_to_file).unwrap();
    let wasm_binary = wat2wasm(&wat.clone()).unwrap();

    let mut m = Module::decode_from(wasm_binary.as_slice()).unwrap();
    let mut bytes = Vec::<u8>::new();
    for s in m.sections.iter_mut() {
        if s.kind() == kind {
            wasmbin_unlazify_with_opt(s, false).unwrap();
            s.encode(&mut bytes).unwrap();
            break
        }
    }

    return bytes;
}

pub fn wat_extract_section_body_bytecode(path_to_file: &str, kind: Kind) -> Vec<u8> {
    let bytecode = &wat_extract_section_bytecode(path_to_file, kind)[..];
    if bytecode.len() <= 0 { return vec![] }
    let last_byte_offset = leb128_compute_last_byte_offset(bytecode, 1).unwrap();
    return  bytecode[last_byte_offset + 1..].to_vec();
}

pub fn wasmbin_unlazify_with_opt<T: Visit>(wasm: &mut T, include_raw: bool) -> Result<(), DecodeError> {
    let res = if include_raw {
        wasm.visit(|()| {})
    } else {
        wasm.visit_mut(|()| {})
    };
    match res {
        Ok(()) => Ok(()),
        Err(err) => match err {
            VisitError::LazyDecode(err) => Err(err),
            VisitError::Custom(err) => match err {},
        },
    }
}
