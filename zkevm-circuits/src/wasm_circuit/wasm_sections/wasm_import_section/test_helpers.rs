use crate::wasm_circuit::leb128_circuit::helpers::leb128_convert;
use crate::wasm_circuit::wasm_sections::wasm_import_section::wasm_import_section_body::consts::ImportDescType;

#[derive(Copy, Clone)]
pub struct ImportDesc {
    pub val_type: ImportDescType,
    pub val: u64,
}

#[derive(Clone)]
pub struct ImportSectionBodyItemDescriptor {
    pub mod_name: String,
    pub import_name: String,
    pub import_desc: ImportDesc,
}

#[derive(Clone)]
pub struct ImportSectionBodyDescriptor {
    pub items: Vec<ImportSectionBodyItemDescriptor>,
}

pub fn generate_import_section_importdesc_bytecode(import_desc: &ImportDesc) -> Vec<u8> {
    let mut bytecode: Vec<u8> = vec![import_desc.val_type as u8];
    bytecode.extend(leb128_convert(false, import_desc.val as i128));

    return bytecode;
}

pub fn generate_import_section_name_bytecode(name: &str) -> Vec<u8> {
    let name_len = name.len();
    let mut bytecode: Vec<u8> = vec![];
    bytecode.extend(leb128_convert(false, name_len as u64 as i128));
    bytecode.extend(name.as_bytes());

    return bytecode;
}

pub fn generate_import_section_item_bytecode(descriptor: &ImportSectionBodyItemDescriptor) -> Vec<u8> {
    let mut bytecode: Vec<u8> = vec![];
    bytecode.extend(generate_import_section_name_bytecode(&descriptor.mod_name));
    bytecode.extend(generate_import_section_name_bytecode(&descriptor.import_name));
    bytecode.extend(generate_import_section_importdesc_bytecode(&descriptor.import_desc));

    return bytecode;
}

// https://webassembly.github.io/spec/core/binary/modules.html#import-section
// example (hex): [2, d3, 1, 3, 3, 65, 6e, 76, c, 5f, 65, 76, 6d, 5f, 61, 64, 64, 72, 65, 73, 73, 0, 2, 3, 65, 6e, 76, c, 5f, 65, 76, 6d, 5f, 62, 61, 6c, 61, 6e, 63, 65, 0, 3, 3, 65, 6e, 76, a4, 1, 5f, 65, 76, 6d, 5f, 73, 6f, 6d, 65, 5f, 6c, 6f, 6e, 67, 5f, 6e, 61, 6d, 65, 5f, 66, 75, 6e, 63, 5f, 73, 6f, 6d, 65, 5f, 6c, 6f, 6e, 67, 5f, 6e, 61, 6d, 65, 5f, 66, 75, 6e, 63, 5f, 73, 6f, 6d, 65, 5f, 6c, 6f, 6e, 67, 5f, 6e, 61, 6d, 65, 5f, 66, 75, 6e, 63, 5f, 73, 6f, 6d, 65, 5f, 6c, 6f, 6e, 67, 5f, 6e, 61, 6d, 65, 5f, 66, 75, 6e, 63, 5f, 73, 6f, 6d, 65, 5f, 6c, 6f, 6e, 67, 5f, 6e, 61, 6d, 65, 5f, 66, 75, 6e, 63, 5f, 73, 6f, 6d, 65, 5f, 6c, 6f, 6e, 67, 5f, 6e, 61, 6d, 65, 5f, 66, 75, 6e, 63, 5f, 73, 6f, 6d, 65, 5f, 6c, 6f, 6e, 67, 5f, 6e, 61, 6d, 65, 5f, 66, 75, 6e, 63, 5f, 73, 6f, 6d, 65, 5f, 6c, 6f, 6e, 67, 5f, 6e, 61, 6d, 65, 5f, 66, 75, 6e, 63, 0, 5]
pub fn generate_import_section_body_bytecode(descriptor: &ImportSectionBodyDescriptor) -> Vec<u8> {
    let items_count = descriptor.items.len();
    let mut bytecode: Vec<u8> = vec![];
    bytecode.extend(leb128_convert(false, items_count as i128));
    for item in &descriptor.items {
        bytecode.extend(generate_import_section_item_bytecode(item));
    }

    return bytecode;
}

#[cfg(test)]
mod test_helpers {
    use ethers_core::k256::pkcs8::der::Encode;
    use log::debug;
    use crate::wasm_circuit::wasm_sections::wasm_import_section::test_helpers::{generate_import_section_body_bytecode, generate_import_section_item_bytecode, ImportDesc, ImportSectionBodyDescriptor, ImportSectionBodyItemDescriptor};
    use crate::wasm_circuit::wasm_sections::wasm_import_section::wasm_import_section_body::consts::ImportDescType;

    #[test]
    pub fn generate_import_section_body_bytecode_test() {
        // expected (hex): [3, 3, 65, 6e, 76, c, 5f, 65, 76, 6d, 5f, 61, 64, 64, 72, 65, 73, 73, 0, 2, 3, 65, 6e, 76, c, 5f, 65, 76, 6d, 5f, 62, 61, 6c, 61, 6e, 63, 65, 0, 3, 3, 65, 6e, 76, a4, 1, 5f, 65, 76, 6d, 5f, 73, 6f, 6d, 65, 5f, 6c, 6f, 6e, 67, 5f, 6e, 61, 6d, 65, 5f, 66, 75, 6e, 63, 5f, 73, 6f, 6d, 65, 5f, 6c, 6f, 6e, 67, 5f, 6e, 61, 6d, 65, 5f, 66, 75, 6e, 63, 5f, 73, 6f, 6d, 65, 5f, 6c, 6f, 6e, 67, 5f, 6e, 61, 6d, 65, 5f, 66, 75, 6e, 63, 5f, 73, 6f, 6d, 65, 5f, 6c, 6f, 6e, 67, 5f, 6e, 61, 6d, 65, 5f, 66, 75, 6e, 63, 5f, 73, 6f, 6d, 65, 5f, 6c, 6f, 6e, 67, 5f, 6e, 61, 6d, 65, 5f, 66, 75, 6e, 63, 5f, 73, 6f, 6d, 65, 5f, 6c, 6f, 6e, 67, 5f, 6e, 61, 6d, 65, 5f, 66, 75, 6e, 63, 5f, 73, 6f, 6d, 65, 5f, 6c, 6f, 6e, 67, 5f, 6e, 61, 6d, 65, 5f, 66, 75, 6e, 63, 5f, 73, 6f, 6d, 65, 5f, 6c, 6f, 6e, 67, 5f, 6e, 61, 6d, 65, 5f, 66, 75, 6e, 63, 0, 5];
        let expected = [3, 3, 101, 110, 118, 12, 95, 101, 118, 109, 95, 97, 100, 100, 114, 101, 115, 115, 0, 2, 3, 101, 110, 118, 12, 95, 101, 118, 109, 95, 98, 97, 108, 97, 110, 99, 101, 0, 3, 3, 101, 110, 118, 164, 1, 95, 101, 118, 109, 95, 115, 111, 109, 101, 95, 108, 111, 110, 103, 95, 110, 97, 109, 101, 95, 102, 117, 110, 99, 95, 115, 111, 109, 101, 95, 108, 111, 110, 103, 95, 110, 97, 109, 101, 95, 102, 117, 110, 99, 95, 115, 111, 109, 101, 95, 108, 111, 110, 103, 95, 110, 97, 109, 101, 95, 102, 117, 110, 99, 95, 115, 111, 109, 101, 95, 108, 111, 110, 103, 95, 110, 97, 109, 101, 95, 102, 117, 110, 99, 95, 115, 111, 109, 101, 95, 108, 111, 110, 103, 95, 110, 97, 109, 101, 95, 102, 117, 110, 99, 95, 115, 111, 109, 101, 95, 108, 111, 110, 103, 95, 110, 97, 109, 101, 95, 102, 117, 110, 99, 95, 115, 111, 109, 101, 95, 108, 111, 110, 103, 95, 110, 97, 109, 101, 95, 102, 117, 110, 99, 95, 115, 111, 109, 101, 95, 108, 111, 110, 103, 95, 110, 97, 109, 101, 95, 102, 117, 110, 99, 0, 5].as_slice().to_vec();
        let descriptor = ImportSectionBodyDescriptor {
            items: vec![
                ImportSectionBodyItemDescriptor {
                    mod_name: "env".to_string(),
                    import_name: "_evm_address".to_string(),
                    import_desc: ImportDesc { val_type: ImportDescType::Type, val: 2, },
                },
                ImportSectionBodyItemDescriptor {
                    mod_name: "env".to_string(),
                    import_name: "_evm_balance".to_string(),
                    import_desc: ImportDesc { val_type: ImportDescType::Type, val: 3, },
                },
                ImportSectionBodyItemDescriptor {
                    mod_name: "env".to_string(),
                    import_name: "_evm_some_long_name_func_some_long_name_func_some_long_name_func_some_long_name_func_some_long_name_func_some_long_name_func_some_long_name_func_some_long_name_func".to_string(),
                    import_desc: ImportDesc { val_type: ImportDescType::Type, val: 5, },
                },
            ],
        };

        let bytecode = generate_import_section_body_bytecode(&descriptor);
        assert_eq!(expected, bytecode);
    }
}