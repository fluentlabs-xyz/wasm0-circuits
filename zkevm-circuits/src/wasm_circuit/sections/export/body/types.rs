#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum AssignType {
    QFirst,
    QLast,

    IsItemsCount,
    IsExportNameLen,
    IsExportName,
    IsExportdescType,
    IsExportdescVal,

    IsExportdescTypeCtx,
    ExportdescType,

    BodyByteRevIndex,

    BodyItemRevCount,
}
