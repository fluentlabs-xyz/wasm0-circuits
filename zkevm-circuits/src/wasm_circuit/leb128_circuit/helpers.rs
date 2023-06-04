use num_traits::pow;

pub fn leb_compute_sn_recovered_at_position(
    sn_recovered_at_prev_pos: u64,
    is_signed: bool,
    byte_offset: usize,
    byte_val: u64,
    last_byte_index: usize,
) -> u64 {
    let is_last_leb_byte = byte_offset == last_byte_index;
    let is_byte_has_cb = byte_offset < last_byte_index;
    let is_consider_byte = byte_offset <= last_byte_index;
    let mut sn_recovered_at_pos = 0;
    if is_consider_byte {
        let leb_byte_mul: u64 = pow(0b10000000, byte_offset);
        sn_recovered_at_pos = sn_recovered_at_prev_pos + (byte_val - if is_byte_has_cb { 0b10000000 } else { 0 }) * leb_byte_mul;
    }
    if is_signed && is_last_leb_byte {
        let number_for_signed_revert = pow(0b10000000, byte_offset + 1) - 1;
        sn_recovered_at_pos = number_for_signed_revert - (sn_recovered_at_pos - 1);
    }

    sn_recovered_at_pos
}
