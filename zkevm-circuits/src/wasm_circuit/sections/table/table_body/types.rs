#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum AssignType {
    IsReferenceTypeCount,
    IsReferenceType,
    IsLimitType,
    IsLimitMin,
    IsLimitMax,
}
