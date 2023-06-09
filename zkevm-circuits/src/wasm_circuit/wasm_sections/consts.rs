use crate::wasm_circuit::wasm_sections::consts::WasmSectionId::DataCount;

pub enum WasmSectionId {
    Custom = 0, // = 0
    Type,
    Import,
    Function,
    Table,
    Memory,
    Global,
    Export,
    Start,
    Element,
    Code,
    Data,
    DataCount,
}

pub const WASM_SECTION_ID_MAX: usize = DataCount as usize;

/// https://webassembly.github.io/spec/core/binary/types.html#number-types
pub enum NumType {
    I32 = 0x7F,
    I64 = 0x7E,
    F32 = 0x7D,
    F64 = 0x7C,
}

// TODO make it differ from custom section id (which is 0 too)
pub const ID_OF_SECTION_DEFAULT: i32 = 0;
