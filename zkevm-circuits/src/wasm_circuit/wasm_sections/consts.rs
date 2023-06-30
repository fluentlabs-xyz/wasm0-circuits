#[derive(Copy, Clone, Debug)]
pub struct LebParams {
    pub byte_rel_offset: usize,
    pub last_byte_rel_offset: usize,
    pub sn: u64,
    pub sn_recovered_at_pos: u64,
}