#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum AssignType {
    Unknown,
    ReferenceTypeCount,
    ReferenceType,
    LimitType,
    LimitMin,
    LimitMax,
}
