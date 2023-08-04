#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum AssignType {
    QFirst,
    QLast,

    LimitType,

    IsItemsCount,
    IsLimitType,
    IsLimitMin,
    IsLimitMax,

    IsLimitTypeCtx,
    BodyItemRevCount,
}
