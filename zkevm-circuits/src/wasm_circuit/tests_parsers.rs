#[cfg(test)]
mod wasm_parsers_tests {
    use num::checked_pow;
    use wabt::wat2wasm;
    use wasmbin::io::Encode;
    use wasmbin::Module;
    use wasmbin::sections::Kind;
    use wasmbin::visit::Visit;

    use crate::wasm_circuit::common::wasmbin_unlazify_with_opt;

    /// returns section len and quantity of leb bytes
    fn compute_section_len(wasm_bytes: &Vec<u8>) -> (u32, u8) {
        let mut section_len: u32 = 0;
        const BASE_INDEX: usize = 1;
        let mut i = BASE_INDEX;
        loop {
            let byte = wasm_bytes[i];
            let mut byte_val: u32 = (byte & 0b1111111) as u32;
            byte_val = byte_val * checked_pow(0b10000000, i - BASE_INDEX).unwrap();
            section_len += byte_val;
            if byte & 0b10000000 == 0 { break }
            i += 1;
        }
        (section_len, (i - BASE_INDEX + 1) as u8)
    }

    #[test]
    pub fn test_print_parsed_file_contents() {
        let path_to_file = "./src/wasm_circuit/test_data/files/cc1.wat";
        // let path_to_file = "./src/wasm_circuit/test_data/files/cc2.wat";
        let wat: Vec<u8> = std::fs::read(path_to_file).unwrap();
        println!("SOURCE WAT: {}", std::str::from_utf8(wat.as_slice()).unwrap());
        let mut wasm_binary = wat2wasm(wat.clone()).unwrap();

        let data = wat2wasm(&wat.clone()).unwrap();
        println!("");
        println!("PARSED {}:", path_to_file);
        println!("data len: {}", data.len());
        println!("data raw (hex): {:x?}", data);
        println!("data raw (decimal): {:?}", data);

        let mut m = Module::decode_from(data.as_slice()).unwrap();
        for s in m.sections.iter_mut() {
            wasmbin_unlazify_with_opt(s, false).unwrap();
            println!("---Kind::{:?}:", s.kind());
            let mut bytes = Vec::<u8>::new();
            s.encode(&mut bytes).unwrap();
            println!("section len: {:?}", compute_section_len(&bytes));
            println!("raw (hex): {:x?}", bytes);
            println!("raw (decimal): {:?}", bytes);
            println!("{:#?}", s);
            match s.kind() {
                Kind::Type => {}
                Kind::Code => {
                    for c1 in s.try_as_mut::<wasmbin::sections::payload::Code>().into_iter().enumerate() {
                        let code_contents = c1.1.try_contents().unwrap();
                        for c2 in code_contents.as_slice() {
                            let fb = c2.try_contents().unwrap();
                            for local in fb.locals.as_slice() {
                                // local.
                            }
                            for exp in fb.expr.as_slice() {}
                        }
                    };
                    println!("{:#?}", s);
                },
                Kind::Table => {},
                Kind::Custom => {}
                Kind::Element => {}
                Kind::DataCount => {}
                Kind::Import => {}
                Kind::Function => {}
                Kind::Memory => {}
                Kind::Global => {}
                Kind::Export => {}
                Kind::Start => {}
                Kind::Data => {}

                _ => {println!("UNPROCESSED/UNKNOWN section '{:?}'", s.kind())}
            }
        }
        println!("Found {} sections.", m.sections.len());
    }
}