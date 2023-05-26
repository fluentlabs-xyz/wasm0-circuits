use std::convert::Into;
use crate::wasm_circuit::consts::WasmSectionId::DataCount;

///
pub static WASM_VERSION_PREFIX_BASE_INDEX: usize = 4;
///
pub static WASM_VERSION_PREFIX_LENGTH: usize = 4;
///
pub static WASM_SECTIONS_START_INDEX: usize = WASM_VERSION_PREFIX_BASE_INDEX + WASM_VERSION_PREFIX_LENGTH;
///
pub static WASM_PREAMBLE_MAGIC_PREFIX: &'static str = "\0asm";
///
pub enum WasmSectionId {
    ///
    Custom, // = 0
    ///
    Type,
    ///
    Import,
    ///
    Function,
    ///
    Table,
    ///
    Memory,
    ///
    Global,
    ///
    Export,
    ///
    Start,
    ///
    Element,
    ///
    Code,
    ///
    Data,
    ///
    DataCount,
}

pub const WASM_SECTION_ID_MAX: usize = DataCount as usize;

// TODO better to make it differ from custom section id (which is 0 too) or
pub const ID_OF_SECTION_DEFAULT: i32 = 0;
