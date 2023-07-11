#[derive(Copy, Clone, Default, Debug)]
pub struct LebParams {
    pub is_signed: bool,
    pub byte_rel_offset: usize,
    pub last_byte_rel_offset: usize,
    pub sn: u64,
    pub sn_recovered_at_pos: u64,
}

impl LebParams {
    pub fn is_first_byte(&self) -> bool {
        self.byte_rel_offset == 0
    }

    pub fn is_last_byte(&self) -> bool {
        self.byte_rel_offset == self.last_byte_rel_offset
    }

    pub fn is_byte_has_cb(&self) -> bool {
        self.byte_rel_offset < self.last_byte_rel_offset
    }
}
