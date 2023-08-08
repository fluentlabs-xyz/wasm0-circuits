#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum AssignType {
    QFirst,
    QLast,

    GlobalType,

    IsItemsCount,
    IsGlobalType,
    IsGlobalTypeCtx,
    IsMutProp,
    IsInitOpcode,
    IsInitVal,
    IsExprDelimiter,

    BodyItemRevCount,
}
