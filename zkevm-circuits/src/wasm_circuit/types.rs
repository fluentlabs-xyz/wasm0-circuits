#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum AssignType {
    Unknown,
    QFirst,
    QLast,
    IsSectionId,
    IsSectionLen,
    IsSectionBody,
}

#[derive(Copy, Clone, Debug, Default)]
pub struct SharedState {
    pub dynamic_indexes_offset: usize,
}
