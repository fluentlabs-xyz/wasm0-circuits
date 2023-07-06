use rand::Rng;
use crate::wasm_circuit::consts::NumType;
use crate::wasm_circuit::leb128_circuit::helpers::leb128_convert;
use crate::wasm_circuit::wasm_sections::r#type::type_item::consts::Type::FuncType;

// https://webassembly.github.io/spec/core/binary/types.html#binary-functype
// example (hex): [0x60, 0x2, 0x7e, 0x7f, 0x1, 0x7f]
pub fn generate_type_section_functype_bytecode(input_count: u64, output_count: u64) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let param_types: Vec<u8> = vec![NumType::I32 as u8, NumType::I64 as u8];
    let mut bytecode: Vec<u8> = vec![FuncType as u8];
    bytecode.extend(leb128_convert(false, input_count as i128));
    for i in 0..input_count {
        let i = rng.gen_range(0..param_types.len());
        bytecode.push(param_types[i]);
    }
    bytecode.extend(leb128_convert(false, output_count as i128));
    for i in 0..output_count {
        let i = rng.gen_range(0..param_types.len());
        bytecode.push(param_types[i]);
    }

    return bytecode;
}

// https://webassembly.github.io/spec/core/binary/modules.html#type-section
// example (hex): [0x4, 0x60, 0, 0, 0x60, 0, 0, 0x60, 0x2, 0x7f, 0x7e, 0, 0x60, 0x2, 0x7e, 0x7f, 0x1, 0x7f]
pub fn generate_type_section_body_bytecode(body_items_count: u64, item_input_count_max: u64, item_output_count_max: u64) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let mut bytecode: Vec<u8> = vec![];
    bytecode.extend(leb128_convert(false, body_items_count as i128));
    for i in 0..body_items_count {
        let input_count = rng.gen_range(0..item_input_count_max);
        let output_count = rng.gen_range(0..item_output_count_max);
        let item_bytecode = generate_type_section_functype_bytecode(input_count, output_count);
        bytecode.extend(item_bytecode);
    }

    return bytecode;
}