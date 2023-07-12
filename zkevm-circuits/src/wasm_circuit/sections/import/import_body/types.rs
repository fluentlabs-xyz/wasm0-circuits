#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum AssignType {
    IsItemsCount,
    IsModNameLen,
    IsModName,
    IsImportNameLen,
    IsImportName,
    IsImportdescType,
    ImportdescType,
    IsImportdescTypeCtx,
    IsImportdescVal,
    IsMut,
}
