#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum AssignType {
    QFirst,
    QLast,

    IsItemsCount,
    IsGlobalType,
    IsMutProp,
    IsInitOpcode,
    IsInitVal,
    IsExprDelimiter,
}
