#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum AssignType {
    Unknown,
    QFirst,
    QLast,
    IsSectionId,
    IsSectionLen,
    IsSectionBody,

    BodyByteRevIndexL1,
}

#[derive(Copy, Clone, Debug, Default)]
pub struct SharedState {
    pub dynamic_indexes_offset: usize,
    pub func_count: usize,
    pub block_level: usize,
}

impl SharedState {
    pub fn reset(&mut self) {
        self.dynamic_indexes_offset = 0;
        self.func_count = 0;
        self.block_level = 0;
    }
}