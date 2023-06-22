// https://webassembly.github.io/spec/core/binary/modules.html#binary-importdesc
#[derive(Copy, Clone)]
pub enum ImportDescType {
    Type = 0x0,
    Table = 0x1,
    Mem = 0x2,
    Global = 0x3,
}
