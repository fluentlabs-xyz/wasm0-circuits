use crate::wasm_circuit::consts::NumericInstruction::{I32Const, I64Const};
use crate::wasm_circuit::consts::{NumType, WASM_EXPR_DELIMITER, WASM_SECTION_ID_MAX};
use crate::wasm_circuit::leb128_circuit::helpers::leb128_convert;

#[derive(Copy, Clone)]
pub struct WasmGlobalSectionBodyItemDescriptor {
    pub global_type: NumType,
    pub is_mut: bool,
    pub init_val: i128,
}

#[derive(Clone)]
pub struct WasmGlobalSectionBodyDescriptor {
    pub funcs: Vec<WasmGlobalSectionBodyItemDescriptor>,
}

pub fn generate_wasm_global_section_item_bytecode(descriptor: &WasmGlobalSectionBodyItemDescriptor) -> Vec<u8> {
    let mut bytecode: Vec<u8> = vec![];
    bytecode.push(descriptor.global_type as u8);
    bytecode.push(descriptor.is_mut as u8);
    match descriptor.global_type {
        NumType::I32 => {
            bytecode.push(I32Const as u8);
            bytecode.extend(leb128_convert(true, descriptor.init_val));
        }
        NumType::I64 => {
            bytecode.push(I64Const as u8);
            bytecode.extend(leb128_convert(true, descriptor.init_val));
        }
        NumType::F32 => {panic!("unsupported type F32")}
        NumType::F64 => {panic!("unsupported type F64")}
    }
    bytecode.push(WASM_EXPR_DELIMITER as u8);

    return bytecode;
}

// https://webassembly.github.io/spec/core/binary/modules.html#code-section
// example (hex, first two bytes are section_id(10=0xA) and section_leb_len):
// is_items_count+ -> item+(is_global_type{1} -> is_mut_prop{1} -> is_init_opcode{1} -> is_init_val+ -> is_expr_delimiter{1})
// raw (hex): [6, 12, 3, 7f, 1, 41, 0, b, 7e, 1, 42, 0, b, 7e, 1, 42, d1, df, 4, b]
// raw (decimal): [6, 18, 3, 127, 1, 65, 0, 11, 126, 1, 66, 0, 11, 126, 1, 66, 209, 223, 4, 11]
// raw (hex): [
// 6, - section id
// 12, - section body len
// 3, - items count
// 7f, 1, - I32, mut
// 41, 0, - i32.const 0
// b, - WASM_EXPR_DELIMITER
// 7e, 1, - i64, mut
// 42, 0, - i64.const 0
// b, - WASM_EXPR_DELIMITER
// 7e, 1, - i64, mut
// 42, d1, df, 4, - i64.const 77777
// b - WASM_EXPR_DELIMITER
// ]
// '77777' in s-leb hex [d1, df, 4]
// 'js' in hex [6a, 73] in decimal [106, 115]
// 'global' in hex [67, 6c, 6f, 62, 61, 6c] in decimal [103, 108, 111, 98, 97, 108]
pub fn generate_wasm_global_section_body_bytecode(descriptor: &WasmGlobalSectionBodyDescriptor) -> Vec<u8> {
    let items_count = descriptor.funcs.len();
    let mut bytecode: Vec<u8> = vec![];
    bytecode.extend(leb128_convert(false, items_count as i128));
    for item in &descriptor.funcs {
        bytecode.extend(generate_wasm_global_section_item_bytecode(item));
    }

    return bytecode;
}

#[cfg(test)]
mod test_helpers {
    use crate::wasm_circuit::consts::NumType;
    use crate::wasm_circuit::wasm_sections::wasm_global_section::test_helpers::{generate_wasm_global_section_body_bytecode, WasmGlobalSectionBodyDescriptor, WasmGlobalSectionBodyItemDescriptor};

    #[test]
    pub fn generate_wasm_global_section_body_bytecode_test() {
        // expected
        // (hex): [3, 7f, 1, 41, 0, b, 7e, 1, 42, 0, b, 7e, 1, 42, d1, df, 4, b]
        let expected = [3, 127, 1, 65, 0, 11, 126, 1, 66, 0, 11, 126, 1, 66, 209, 223, 4, 11].as_slice().to_vec();
        let descriptor = WasmGlobalSectionBodyDescriptor {
            funcs: vec![
                WasmGlobalSectionBodyItemDescriptor {
                    global_type: NumType::I32,
                    is_mut: true,
                    init_val: 0,
                },
                WasmGlobalSectionBodyItemDescriptor {
                    global_type: NumType::I64,
                    is_mut: true,
                    init_val: 0,
                },
                WasmGlobalSectionBodyItemDescriptor {
                    global_type: NumType::I64,
                    is_mut: true,
                    init_val: 77777,
                },
            ],
        };

        let bytecode = generate_wasm_global_section_body_bytecode(&descriptor);
        assert_eq!(expected, bytecode);
    }
}