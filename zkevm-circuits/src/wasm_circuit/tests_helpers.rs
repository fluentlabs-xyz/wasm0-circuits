use rand::random;

pub fn break_bit(byte_to_break: &mut u8, break_mask: u8) {
    *byte_to_break = (!*byte_to_break & break_mask) | (*byte_to_break & !break_mask);
}

pub fn mutate_byte(byte_to_mutate: &mut u8) {
    let mut byte_new_val = *byte_to_mutate;
    while byte_new_val == *byte_to_mutate { byte_new_val = random(); }
}