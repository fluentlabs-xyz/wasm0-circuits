use crate::wasm_circuit::leb128_circuit::helpers::leb128_convert;

#[derive(Clone)]
pub struct FunctionSectionBodyItemDescriptor {
    pub typeidx: u64,
}

#[derive(Clone)]
pub struct FunctionSectionBodyDescriptor {
    pub items: Vec<FunctionSectionBodyItemDescriptor>,
}

pub fn generate_function_section_item_bytecode(descriptor: &FunctionSectionBodyItemDescriptor) -> Vec<u8> {
    let mut bytecode: Vec<u8> = vec![];
    bytecode.extend(leb128_convert(false, descriptor.typeidx));

    return bytecode;
}

// https://webassembly.github.io/spec/core/binary/modules.html#function-section
// example (hex, first two bytes are section_id and section_leb_len): [3, 3, 2, 0, 1]
pub fn generate_function_section_body_bytecode(descriptor: &FunctionSectionBodyDescriptor) -> Vec<u8> {
    let items_count = descriptor.items.len();
    let mut bytecode: Vec<u8> = vec![];
    bytecode.extend(leb128_convert(false, items_count as u64));
    for item in &descriptor.items {
        bytecode.extend(generate_function_section_item_bytecode(item));
    }

    return bytecode;
}

#[cfg(test)]
mod test_helpers {
    use crate::wasm_circuit::wasm_sections::wasm_function_section::test_helpers::{FunctionSectionBodyDescriptor, FunctionSectionBodyItemDescriptor, generate_function_section_body_bytecode};

    #[test]
    pub fn generate_function_section_body_bytecode_test() {
        // expected (hex): [2, 0, 1]
        let expected = [2, 0, 1].as_slice().to_vec();
        let descriptor = FunctionSectionBodyDescriptor {
            items: vec![
                FunctionSectionBodyItemDescriptor {
                    typeidx: 0,
                },
                FunctionSectionBodyItemDescriptor {
                    typeidx: 1,
                },
            ],
        };

        let bytecode = generate_function_section_body_bytecode(&descriptor);
        assert_eq!(expected, bytecode);
    }
}