use rand::{random, Rng, thread_rng};

pub fn break_bit_by_mask(byte_to_break: &mut u8, break_mask: u8) {
    *byte_to_break = (!*byte_to_break & break_mask) | (*byte_to_break & !break_mask);
}

pub fn mutate_byte(byte_to_mutate: &mut u8) {
    let mut byte_old_val = *byte_to_mutate;
    while byte_old_val == *byte_to_mutate { *byte_to_mutate = random(); }
}