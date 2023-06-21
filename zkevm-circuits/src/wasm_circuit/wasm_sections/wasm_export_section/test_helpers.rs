use crate::wasm_circuit::leb128_circuit::helpers::leb128_convert;
use crate::wasm_circuit::wasm_sections::consts::LimitsType;
use crate::wasm_circuit::wasm_sections::wasm_export_section::wasm_export_section_body::consts::ExportDesc;

#[derive(Clone)]
pub struct WasmExportSectionBodyItemDescriptor {
    pub export_name: String,
    pub export_desc_type: ExportDesc,
    pub export_desc_val: u64,
}

#[derive(Clone)]
pub struct WasmExportSectionBodyDescriptor {
    pub items: Vec<WasmExportSectionBodyItemDescriptor>,
}

pub fn generate_wasm_export_section_item_bytecode(descriptor: &WasmExportSectionBodyItemDescriptor) -> Vec<u8> {
    let mut bytecode: Vec<u8> = vec![];
    bytecode.extend(leb128_convert(false, descriptor.export_name.len() as i128));
    bytecode.extend(descriptor.export_name.as_bytes());
    bytecode.push(descriptor.export_desc_type as u8);
    bytecode.extend(leb128_convert(false, descriptor.export_desc_val as i128));

    return bytecode;
}

// https://webassembly.github.io/spec/core/binary/modules.html#export-section
// example (hex, first two bytes are section_id(7) and section_leb_len): [7, 11, 2, 4, 6d, 61, 69, 6e, 0, 0, 6, 6d, 65, 6d, 6f, 72, 79, 2, 0]
pub fn generate_wasm_export_section_body_bytecode(descriptor: &WasmExportSectionBodyDescriptor) -> Vec<u8> {
    let items_count = descriptor.items.len();
    let mut bytecode: Vec<u8> = vec![];
    bytecode.extend(leb128_convert(false, items_count as i128));
    for item in &descriptor.items {
        bytecode.extend(generate_wasm_export_section_item_bytecode(item));
    }

    return bytecode;
}

#[cfg(test)]
mod test_helpers {
    use crate::wasm_circuit::wasm_sections::consts::LimitsType;
    use crate::wasm_circuit::wasm_sections::wasm_export_section::test_helpers::{generate_wasm_export_section_body_bytecode, WasmExportSectionBodyDescriptor, WasmExportSectionBodyItemDescriptor};
    use crate::wasm_circuit::wasm_sections::wasm_export_section::wasm_export_section_body::consts::ExportDesc;

    #[test]
    pub fn generate_wasm_export_section_body_bytecode_test() {
        // expected (hex): [2, 4, 6d, 61, 69, 6e, 0, 0, 6, 6d, 65, 6d, 6f, 72, 79, 2, 0]
        let expected = [2, 4, 109, 97, 105, 110, 0, 0, 6, 109, 101, 109, 111, 114, 121, 2, 0].as_slice().to_vec();
        let descriptor = WasmExportSectionBodyDescriptor {
            items: vec![
                WasmExportSectionBodyItemDescriptor {
                    export_name: "main".to_string(),
                    export_desc_type: ExportDesc::FuncExportDesc,
                    export_desc_val: 0,
                },
                WasmExportSectionBodyItemDescriptor {
                    export_name: "memory".to_string(),
                    export_desc_type: ExportDesc::MemExportDesc,
                    export_desc_val: 0,
                },
            ],
        };

        let bytecode = generate_wasm_export_section_body_bytecode(&descriptor);
        assert_eq!(expected, bytecode);
    }
}