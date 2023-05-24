use num_traits::checked_pow;

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
