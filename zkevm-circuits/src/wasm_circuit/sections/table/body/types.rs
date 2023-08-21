#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum AssignType {
    QFirst,
    QLast,

    IsReferenceTypeCount,
    IsReferenceType,
    IsLimitType,
    IsLimitTypeCtx,
    IsLimitMin,
    IsLimitMax,

    LimitType,

    ErrorCode,
}
