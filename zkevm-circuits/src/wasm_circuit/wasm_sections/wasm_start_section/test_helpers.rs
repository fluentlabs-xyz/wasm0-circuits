use crate::wasm_circuit::consts::NumericInstruction::I32Const;
use crate::wasm_circuit::consts::{MemSegmentType, WASM_BLOCK_END};
use crate::wasm_circuit::leb128_circuit::helpers::leb128_convert;

#[derive(Clone)]
pub struct WasmStartSectionBodyItemDescriptor {
    pub mem_segment_type: MemSegmentType,
    pub mem_segment_size: u64,
    pub mem_segment_bytes: Vec<u8>,
}

#[derive(Clone)]
pub struct WasmStartSectionBodyDescriptor {
    pub items: Vec<WasmStartSectionBodyItemDescriptor>,
}

pub fn generate_wasm_start_section_item_bytecode(descriptor: &WasmStartSectionBodyItemDescriptor) -> Vec<u8> {
    let mut bytecode: Vec<u8> = vec![];
    bytecode.push(descriptor.mem_segment_type as u8);
    bytecode.push(I32Const as u8);
    bytecode.extend(leb128_convert(true, descriptor.mem_segment_size as i128));
    bytecode.push(WASM_BLOCK_END as u8);
    bytecode.extend(leb128_convert(false, descriptor.mem_segment_bytes.len() as i128));
    bytecode.extend(descriptor.mem_segment_bytes.clone());

    return bytecode;
}

// https://webassembly.github.io/spec/core/binary/modules.html#data-section
// example (hex, first two bytes are section_id(11=0xB) and section_leb_len):
// items_count+ -> item+(mem_segment_type{1} -> mem_segment_size_opcode{1} -> mem_segment_size+ -> WASM_BLOCK_END -> mem_segment_len+ -> mem_segment_bytes+)
// raw (hex): [b, b5, 1, 2, 0, 41, ff, ff, 3f, b, 4, 6e, 6f, 6e, 65, 0, 41, 80, 80, c0, 0, b, a0, 1, 0, 61, 73, 6d, 1, 0, 0, 0, 1, 9, 2, 60, 2, 7f, 7f, 0, 60, 0, 0, 2, 13, 1, 3, 65, 6e, 76, b, 5f, 65, 76, 6d, 5f, 72, 65, 74, 75, 72, 6e, 0, 0, 3, 2, 1, 1, 5, 3, 1, 0, 11, 6, 19, 3, 7f, 1, 41, 80, 80, c0, 0, b, 7f, 0, 41, 8c, 80, c0, 0, b, 7f, 0, 41, 90, 80, c0, 0, b, 7, 2c, 4, 6, 6d, 65, 6d, 6f, 72, 79, 2, 0, 4, 6d, 61, 69, 6e, 0, 1, a, 5f, 5f, 64, 61, 74, 61, 5f, 65, 6e, 64, 3, 1, b, 5f, 5f, 68, 65, 61, 70, 5f, 62, 61, 73, 65, 3, 2, a, d, 1, b, 0, 41, 80, 80, c0, 0, 41, c, 10, 0, b, b, 15, 1, 0, 41, 80, 80, c0, 0, b, c, 48, 65, 6c, 6c, 6f, 2c, 20, 57, 6f, 72, 6c, 64]
// raw (decimal): [11, 181, 1, 2, 0, 65, 255, 255, 63, 11, 4, 110, 111, 110, 101, 0, 65, 128, 128, 192, 0, 11, 160, 1, 0, 97, 115, 109, 1, 0, 0, 0, 1, 9, 2, 96, 2, 127, 127, 0, 96, 0, 0, 2, 19, 1, 3, 101, 110, 118, 11, 95, 101, 118, 109, 95, 114, 101, 116, 117, 114, 110, 0, 0, 3, 2, 1, 1, 5, 3, 1, 0, 17, 6, 25, 3, 127, 1, 65, 128, 128, 192, 0, 11, 127, 0, 65, 140, 128, 192, 0, 11, 127, 0, 65, 144, 128, 192, 0, 11, 7, 44, 4, 6, 109, 101, 109, 111, 114, 121, 2, 0, 4, 109, 97, 105, 110, 0, 1, 10, 95, 95, 100, 97, 116, 97, 95, 101, 110, 100, 3, 1, 11, 95, 95, 104, 101, 97, 112, 95, 98, 97, 115, 101, 3, 2, 10, 13, 1, 11, 0, 65, 128, 128, 192, 0, 65, 12, 16, 0, 11, 11, 21, 1, 0, 65, 128, 128, 192, 0, 11, 12, 72, 101, 108, 108, 111, 44, 32, 87, 111, 114, 108, 100]
pub fn generate_wasm_start_section_body_bytecode(descriptor: &WasmStartSectionBodyDescriptor) -> Vec<u8> {
    let items_count = descriptor.items.len();
    let mut bytecode: Vec<u8> = vec![];
    bytecode.extend(leb128_convert(false, items_count as i128));
    for item in &descriptor.items {
        bytecode.extend(generate_wasm_start_section_item_bytecode(item));
    }

    return bytecode;
}

#[cfg(test)]
mod test_helpers {
    use log::debug;
    use crate::wasm_circuit::consts::MemSegmentType;
    use crate::wasm_circuit::wasm_sections::wasm_start_section::test_helpers::{generate_wasm_start_section_body_bytecode, WasmStartSectionBodyDescriptor, WasmStartSectionBodyItemDescriptor};

    #[test]
    pub fn generate_wasm_start_section_body_bytecode_test() {
        // expected
        // raw (hex): [2, 0, 41, ff, ff, 3f, b, 4, 6e, 6f, 6e, 65, 0, 41, 80, 80, c0, 0, b, a0, 1, 0, 61, 73, 6d, 1, 0, 0, 0, 1, 9, 2, 60, 2, 7f, 7f, 0, 60, 0, 0, 2, 13, 1, 3, 65, 6e, 76, b, 5f, 65, 76, 6d, 5f, 72, 65, 74, 75, 72, 6e, 0, 0, 3, 2, 1, 1, 5, 3, 1, 0, 11, 6, 19, 3, 7f, 1, 41, 80, 80, c0, 0, b, 7f, 0, 41, 8c, 80, c0, 0, b, 7f, 0, 41, 90, 80, c0, 0, b, 7, 2c, 4, 6, 6d, 65, 6d, 6f, 72, 79, 2, 0, 4, 6d, 61, 69, 6e, 0, 1, a, 5f, 5f, 64, 61, 74, 61, 5f, 65, 6e, 64, 3, 1, b, 5f, 5f, 68, 65, 61, 70, 5f, 62, 61, 73, 65, 3, 2, a, d, 1, b, 0, 41, 80, 80, c0, 0, 41, c, 10, 0, b, b, 15, 1, 0, 41, 80, 80, c0, 0, b, c, 48, 65, 6c, 6c, 6f, 2c, 20, 57, 6f, 72, 6c, 64]
        let expected = [2, 0, 65, 255, 255, 63, 11, 4, 110, 111, 110, 101, 0, 65, 128, 128, 192, 0, 11, 160, 1, 0, 97, 115, 109, 1, 0, 0, 0, 1, 9, 2, 96, 2, 127, 127, 0, 96, 0, 0, 2, 19, 1, 3, 101, 110, 118, 11, 95, 101, 118, 109, 95, 114, 101, 116, 117, 114, 110, 0, 0, 3, 2, 1, 1, 5, 3, 1, 0, 17, 6, 25, 3, 127, 1, 65, 128, 128, 192, 0, 11, 127, 0, 65, 140, 128, 192, 0, 11, 127, 0, 65, 144, 128, 192, 0, 11, 7, 44, 4, 6, 109, 101, 109, 111, 114, 121, 2, 0, 4, 109, 97, 105, 110, 0, 1, 10, 95, 95, 100, 97, 116, 97, 95, 101, 110, 100, 3, 1, 11, 95, 95, 104, 101, 97, 112, 95, 98, 97, 115, 101, 3, 2, 10, 13, 1, 11, 0, 65, 128, 128, 192, 0, 65, 12, 16, 0, 11, 11, 21, 1, 0, 65, 128, 128, 192, 0, 11, 12, 72, 101, 108, 108, 111, 44, 32, 87, 111, 114, 108, 100].as_slice().to_vec();
        let descriptor = WasmStartSectionBodyDescriptor {
            items: vec![
                WasmStartSectionBodyItemDescriptor {
                    mem_segment_type: MemSegmentType::ActiveZero,
                    mem_segment_size: 1048575,
                    mem_segment_bytes: "none".as_bytes().to_vec(),
                },
                WasmStartSectionBodyItemDescriptor {
                    mem_segment_type: MemSegmentType::ActiveZero,
                    mem_segment_size: 1048576,
                    mem_segment_bytes: vec![0, 97, 115, 109, 1, 0, 0, 0, 1, 9, 2, 96, 2, 127, 127, 0, 96, 0, 0, 2, 19, 1, 3, 101, 110, 118, 11, 95, 101, 118, 109, 95, 114, 101, 116, 117, 114, 110, 0, 0, 3, 2, 1, 1, 5, 3, 1, 0, 17, 6, 25, 3, 127, 1, 65, 128, 128, 192, 0, 11, 127, 0, 65, 140, 128, 192, 0, 11, 127, 0, 65, 144, 128, 192, 0, 11, 7, 44, 4, 6, 109, 101, 109, 111, 114, 121, 2, 0, 4, 109, 97, 105, 110, 0, 1, 10, 95, 95, 100, 97, 116, 97, 95, 101, 110, 100, 3, 1, 11, 95, 95, 104, 101, 97, 112, 95, 98, 97, 115, 101, 3, 2, 10, 13, 1, 11, 0, 65, 128, 128, 192, 0, 65, 12, 16, 0, 11, 11, 21, 1, 0, 65, 128, 128, 192, 0, 11, 12, 72, 101, 108, 108, 111, 44, 32, 87, 111, 114, 108, 100],
                },
            ],
        };

        let bytecode = generate_wasm_start_section_body_bytecode(&descriptor);
        debug!("expected {:?}", expected);
        debug!("bytecode {:?}", bytecode);
        debug!("");
        debug!("expected (hex) {:x?}", expected);
        debug!("bytecode (hex) {:x?}", bytecode);
        assert_eq!(expected, bytecode);
    }
}