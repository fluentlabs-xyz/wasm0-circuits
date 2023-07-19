#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum AssignType {
    QFirst,
    QLast,

    LimitType,

    IsLimitType,
    IsLimitMin,
    IsLimitMax,
    IsItemsCount,
    IsModNameLen,
    IsModName,
    IsImportNameLen,
    IsImportName,
    IsImportdescType,
    IsImportdescVal,
    IsMut,

    IsLimitTypeCtx,

    IsImportdescTypeCtx,
    ImportdescType,
}
