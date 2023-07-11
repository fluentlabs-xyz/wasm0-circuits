/// https://webassembly.github.io/spec/core/binary/modules.html#export-section
#[derive(Copy, Clone)]
pub enum ExportDesc {
    FuncExportDesc = 0x0,
    TableExportDesc = 0x1,
    MemExportDesc = 0x2,
    GlobalExportDesc = 0x3,
}