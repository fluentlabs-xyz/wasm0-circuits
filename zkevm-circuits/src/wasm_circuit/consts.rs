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
