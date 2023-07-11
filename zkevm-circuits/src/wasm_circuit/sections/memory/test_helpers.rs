use crate::wasm_circuit::consts::LimitType;
use crate::wasm_circuit::leb128_circuit::helpers::leb128_convert;

#[derive(Clone)]
pub struct WasmMemorySectionBodyItemLimitsDescriptor {
    pub limits_type: LimitType,
    pub min: u64,
    pub max: u64,
}

#[derive(Clone)]
pub struct WasmMemorySectionBodyItemDescriptor {
    pub limits: WasmMemorySectionBodyItemLimitsDescriptor,
}

#[derive(Clone)]
pub struct WasmMemorySectionBodyDescriptor {
    pub items: Vec<WasmMemorySectionBodyItemDescriptor>,
}

pub fn generate_wasm_memory_section_item_bytecode(descriptor: &WasmMemorySectionBodyItemDescriptor) -> Vec<u8> {
    let mut bytecode: Vec<u8> = vec![];
    bytecode.extend(leb128_convert(false, descriptor.limits.limits_type.clone() as i128));
    bytecode.extend(leb128_convert(false, descriptor.limits.min as i128));
    match descriptor.limits.limits_type {
        LimitType::MinMax => {
            bytecode.extend(leb128_convert(false, descriptor.limits.max as i128));
        },
        _ => {}
    }

    return bytecode;
}

// https://webassembly.github.io/spec/core/binary/modules.html#memory-section
// example (hex, first two bytes are section_id(5) and section_leb_len): [5, 3, 1, 0, 1]
pub fn generate_wasm_memory_section_body_bytecode(descriptor: &WasmMemorySectionBodyDescriptor) -> Vec<u8> {
    let items_count = descriptor.items.len();
    let mut bytecode: Vec<u8> = vec![];
    bytecode.extend(leb128_convert(false, items_count as i128));
    for item in &descriptor.items {
        bytecode.extend(generate_wasm_memory_section_item_bytecode(item));
    }

    return bytecode;
}

#[cfg(test)]
mod test_helpers {
    use crate::wasm_circuit::consts::LimitType;
    use crate::wasm_circuit::sections::memory::test_helpers::{generate_wasm_memory_section_body_bytecode, WasmMemorySectionBodyDescriptor, WasmMemorySectionBodyItemDescriptor, WasmMemorySectionBodyItemLimitsDescriptor};

    #[test]
    pub fn generate_wasm_memory_section_body_bytecode_test() {
        // expected (hex): [1, 0, 1]
        let expected = [1, 0, 1].as_slice().to_vec();
        let descriptor = WasmMemorySectionBodyDescriptor {
            items: vec![
                WasmMemorySectionBodyItemDescriptor {
                    limits: WasmMemorySectionBodyItemLimitsDescriptor {
                        limits_type: LimitType::MinOnly,
                        min: 1,
                        max: 0,
                    }
                },
            ],
        };

        let bytecode = generate_wasm_memory_section_body_bytecode(&descriptor);
        assert_eq!(expected, bytecode);
    }
}