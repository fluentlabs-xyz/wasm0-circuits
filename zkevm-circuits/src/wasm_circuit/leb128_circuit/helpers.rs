use num_traits::pow;
use crate::wasm_circuit::error::Error;
use crate::wasm_circuit::leb128_circuit::consts::{EIGHT_MS_BIT_MASK, LEB128_MAX_BYTES_COUNT};

pub fn leb128_compute_sn_recovered_at_position(
    sn_recovered_at_prev_pos: u64,
    is_signed: bool,
    byte_offset: usize,
    last_byte_offset: usize,
    byte_val: u8,
) -> u64 {
    let is_last_leb_byte = byte_offset == last_byte_offset;
    let is_byte_has_cb = byte_offset < last_byte_offset;
    let is_consider_byte = byte_offset <= last_byte_offset;
    let mut sn_recovered_at_pos = 0;
    if is_consider_byte {
        let leb_byte_mul: u64 = pow(0b10000000, byte_offset);
        sn_recovered_at_pos = sn_recovered_at_prev_pos + (byte_val as u64 - if is_byte_has_cb { 0b10000000 } else { 0 }) * leb_byte_mul;
    }
    if is_signed && is_last_leb_byte {
        let number_for_signed_revert = pow(0b10000000, byte_offset + 1) - 1;
        sn_recovered_at_pos = number_for_signed_revert - (sn_recovered_at_pos - 1);
    }

    sn_recovered_at_pos
}

pub fn leb128_compute_last_byte_offset(
    bytes: &[u8],
    leb_first_byte_offset: usize,
) -> Result<usize, Error> {
    let mut offset = leb_first_byte_offset;
    loop {
        if offset >= bytes.len() {
            return Err(Error::IndexOutOfBounds(format!("offset {} when max {}", offset, bytes.len() - 1)))
        }

        if bytes[offset] & EIGHT_MS_BIT_MASK == 0 {
            break
        }

        offset += 1;
        let byte_offset = offset - leb_first_byte_offset;
        if byte_offset >= LEB128_MAX_BYTES_COUNT {
            return Err(Error::UnsupportedBytesCount(format!("bytes count {} when max allowed {}", byte_offset + 1, LEB128_MAX_BYTES_COUNT)))
        }
    }
    Ok(offset)
}

/// returns SN and last byte offset
pub fn leb128_compute_sn(
    bytes: &[u8],
    is_signed: bool,
    first_byte_offset: usize,
) -> Result<(u64, usize), Error> {
    let last_byte_offset = leb128_compute_last_byte_offset(bytes, first_byte_offset)?;
    let mut sn: u64 = 0;
    for offset in first_byte_offset..=last_byte_offset {
        sn = leb128_compute_sn_recovered_at_position(
            sn,
            is_signed,
            offset - first_byte_offset,
            last_byte_offset - first_byte_offset,
            bytes[offset],
        )
    }
    Ok((sn, last_byte_offset))
}

///
pub fn leb128_convert(
    is_signed: bool,
    value: u64,
) -> Vec<u8> {
    let mut res = vec![];

    if is_signed {
        leb128::write::signed(&mut res, -(value as i64)).expect("Failed to convert number to signed leb128");
    } else {
        leb128::write::unsigned(&mut res, value).expect("Failed to convert number to unsigned leb128");
    }

    res
}
