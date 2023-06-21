use crate::wasm_circuit::leb128_circuit::helpers::leb128_convert;
use crate::wasm_circuit::wasm_sections::consts::{LimitsType, NumType};

#[derive(Copy, Clone)]
pub struct WasmCodeSectionBodyFuncDescriptor {
}

#[derive(Clone)]
pub struct WasmCodeSectionBodyDescriptor {
    pub funcs: Vec<WasmCodeSectionBodyFuncDescriptor>,
}

pub fn generate_wasm_code_section_item_bytecode(descriptor: &WasmCodeSectionBodyFuncDescriptor) -> Vec<u8> {
    let mut bytecode: Vec<u8> = vec![];

    return bytecode;
}

// https://webassembly.github.io/spec/core/binary/modules.html#code-section
// example (hex, first two bytes are section_id(10=0xA) and section_leb_len):
// TODO: is_funcs_count+ -> is_func_body_len+ -> locals+(is_valtype_transitions_count+ -> local_var_descriptor+(is_local_repetition_count+ -> is_local_type(1))) -> is_func_body_code
// raw (hex):     [a,  2e, 2, 1d, 1, 1,  7f, 41, 0, 21, 0, 2, 40, 3, 40, 20, 0,  d, 1, 20, 0, 41,  c0,  c4, 7,  6a, 21, 0,  c, 0,  b,  b,  b,  e, 4, 1,  7f, 1,  7e, 2,  7f, 3,  7e, 41, 0, 21, 0, b]
// raw (hex):     [
// a, - section_id
// 2e, - section_body_leb_len
// 2, - funcs_count
// 1d, - func_body_len
// 1, - locals: 1 type transition
// 1, 7f, - locals: 1 repetition of I32
// 41, 0, - func_body_code: i32.const 0
// 21, 0, - func_body_code: local.set 0
// 2, 40, - func_body_code: blocktype.block
//   3, 40, - func_body_code: blocktype.loop
//     20, 0, - func_body_code: local.get 0
//     d, 1, - func_body_code: br_if 1 (;@1;)
//     20, 0, - func_body_code: local.get 0
//     41,  c0,  c4, 7, - func_body_code: i32.const 123456
//     6a, - func_body_code: i32.add
//     21, 0, - func_body_code: local.set 0
//     c, 0, - func_body_code: br 0 (;@2;)
//   b, - func_body_code: blocktype.loop.end
// b, - func_body_code: blocktype.block.end
// b, - func_body_code: func.end
// e, - func_body_len
// 4, - locals: 4 type transitions
// 1,  7f, - locals: 1 repetition of I32
// 1,  7e, - locals: 1 repetition of I64
// 2,  7f, - locals: 2 repetitions of I32
// 3,  7e, - locals: 3 repetitions of I64
// 41, 0, - func_body_code: i32.const 0
// 21, 0, - func_body_code: local.set 0
// b - func end
// ]
// raw (decimal): [10, 46, 2, 29, 1, 1, 127, 65, 0, 33, 0, 2, 64, 3, 64, 32, 0, 13, 1, 32, 0, 65, 192, 196, 7, 106, 33, 0, 12, 0, 11, 11, 11, 14, 4, 1, 127, 1, 126, 2, 127, 3, 126, 65, 0, 33, 0, 11]
pub fn generate_wasm_code_section_body_bytecode(descriptor: &WasmCodeSectionBodyDescriptor) -> Vec<u8> {
    let items_count = descriptor.funcs.len();
    let mut bytecode: Vec<u8> = vec![];
    bytecode.extend(leb128_convert(false, items_count as i128));
    for item in &descriptor.funcs {
        bytecode.extend(generate_wasm_code_section_item_bytecode(item));
    }

    return bytecode;
}

#[cfg(test)]
mod test_helpers {
    use crate::wasm_circuit::wasm_sections::consts::{LimitsType, NumType};
    use crate::wasm_circuit::wasm_sections::wasm_code_section::test_helpers::{generate_wasm_code_section_body_bytecode, WasmCodeSectionBodyDescriptor, WasmCodeSectionBodyFuncDescriptor};

    #[test]
    pub fn generate_wasm_code_section_body_bytecode_test() {
        // expected
        // (hex): [2, 1d, 1, 1,  7f, 41, 0, 21, 0, 2, 40, 3, 40, 20, 0,  d, 1, 20, 0, 41,  c0,  c4, 7,  6a, 21, 0,  c, 0,  b,  b,  b,  e, 4, 1,  7f, 1,  7e, 2,  7f, 3,  7e, 41, 0, 21, 0, b]
        let expected = [2, 29, 1, 1, 127, 65, 0, 33, 0, 2, 64, 3, 64, 32, 0, 13, 1, 32, 0, 65, 192, 196, 7, 106, 33, 0, 12, 0, 11, 11, 11, 14, 4, 1, 127, 1, 126, 2, 127, 3, 126, 65, 0, 33, 0, 11].as_slice().to_vec();
        let descriptor = WasmCodeSectionBodyDescriptor {
            funcs: vec![
                WasmCodeSectionBodyFuncDescriptor {
                },
            ],
        };

        let bytecode = generate_wasm_code_section_body_bytecode(&descriptor);
        assert_eq!(expected, bytecode);
    }
}