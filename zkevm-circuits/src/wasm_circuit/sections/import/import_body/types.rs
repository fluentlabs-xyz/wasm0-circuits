#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum AssignType {
    QFirst,
    QLast,

    IsItemsCount,
    IsModNameLen,
    IsModName,
    IsImportNameLen,
    IsImportName,
    IsImportdescType,
    IsImportdescVal,
    IsMut,

    IsImportdescTypeCtx,
    ImportdescType,
}
