use crate::wasm_circuit::types::WasmSection;

pub const MAX_LEB128_BYTES: usize = 5;
pub static WASM_MAGIC_PREFIX: &'static str = "\0asm";
pub static WASM_MAGIC_PREFIX_LEN: usize = WASM_MAGIC_PREFIX.len();
pub static WASM_MAGIC_PREFIX_START_INDEX: usize = 0;
pub static WASM_MAGIC_PREFIX_END_INDEX: usize = WASM_MAGIC_PREFIX_LEN - 1;
pub static WASM_VERSION_PREFIX: &'static str = "1000";
pub static WASM_VERSION_PREFIX_LEN: usize = WASM_VERSION_PREFIX.len();
pub static WASM_VERSION_PREFIX_START_INDEX: usize = WASM_MAGIC_PREFIX_END_INDEX + 1;
pub static WASM_VERSION_PREFIX_END_INDEX: usize =
    WASM_VERSION_PREFIX_START_INDEX + WASM_VERSION_PREFIX_LEN - 1;
pub static WASM_SECTIONS_START_INDEX: usize = WASM_VERSION_PREFIX_END_INDEX + 1;
pub static WASM_BLOCK_END: u8 = 0xB;
pub static WASM_BLOCKTYPE_DELIMITER: i32 = 0x40;
pub const WASM_SECTION_ID_MAX: usize = WasmSection::DataCount as usize;

// TODO make it differ from custom section id (which is 0 too)
pub const SECTION_ID_DEFAULT: i32 = 0;
