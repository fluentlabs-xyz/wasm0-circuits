#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum AssignType {
    IsItemsCount,
    IsExportNameLen,
    IsExportName,
    IsExportdescType,
    IsExportdescVal,

    IsExportdescTypeCtx,
    ExportdescType,
}
