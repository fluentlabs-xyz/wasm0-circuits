#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum AssignType {
    ReferenceTypeCount,
    ReferenceType,
    LimitType,
    LimitMin,
    LimitMax,
}
