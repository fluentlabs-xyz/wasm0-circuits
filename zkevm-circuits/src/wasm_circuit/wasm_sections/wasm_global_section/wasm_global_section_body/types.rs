#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum AssignType {
    IsItemsCount,
    IsGlobalType,
    IsMutProp,
    IsInitOpcode,
    IsInitVal,
    IsExprDelimiter,
}
