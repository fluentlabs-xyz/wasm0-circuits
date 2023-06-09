// https://webassembly.github.io/spec/core/binary/modules.html#binary-importdesc
#[derive(Copy, Clone)]
pub enum ImportDescType {
    TypeImportDescType = 0x0,
    // TODO add support?
    // TableImportDescType = 0x1,
    // MemImportDescType = 0x2,
    // GlobalImportDescType = 0x3,
}
