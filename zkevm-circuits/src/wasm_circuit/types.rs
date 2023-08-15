#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum AssignType {
    Unknown,
    QFirst,
    QLast,
    IsSectionId,
    IsSectionLen,
    IsSectionBody,

    BodyByteRevIndexL1,

    ErrorCode,
}

#[derive(Copy, Clone, Debug)]
pub enum ErrorCode {
    Ok = 0,
    Error = 1,
}

#[derive(Copy, Clone, Debug, Default)]
pub struct SharedState {
    pub dynamic_indexes_offset: usize,
    pub func_count: usize,
    pub block_level: usize,

    pub error_processing_enabled: bool,
    pub error_code: u64,
}

impl SharedState {
    pub fn reset(&mut self) {
        self.dynamic_indexes_offset = 0;
        self.func_count = 0;
        self.block_level = 0;
        self.error_processing_enabled = false;
        self.error_code = 0;
    }

    pub fn set_error_code_on(&mut self) {
        self.error_code = 1;
    }
}