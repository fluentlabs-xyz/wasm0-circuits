#[cfg(test)]
mod wasm_parsers_tests {
    use num::checked_pow;
    use wabt::wat2wasm;
    use wasmbin::io::DecodeError;
    use wasmbin::io::Encode;
    use wasmbin::Module;
    use wasmbin::sections::Kind;
    use wasmbin::visit::{Visit, VisitError};

    fn unlazify_with_opt<T: Visit>(wasm: &mut T, include_raw: bool) -> Result<(), DecodeError> {
        let res = if include_raw {
            wasm.visit(|()| {})
        } else {
            wasm.visit_mut(|()| {})
        };
        match res {
            Ok(()) => Ok(()),
            Err(err) => match err {
                VisitError::LazyDecode(err) => Err(err),
                VisitError::Custom(err) => match err {},
            },
        }
    }

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
        // let path_to_file = "./src/wasm_circuit/test_data/files/br_breaks_1.wat";
        let path_to_file = "./src/wasm_circuit/test_data/files/block_loop_local_vars.wat";
        println!("PARSED {}", path_to_file);
        let data: Vec<u8> = std::fs::read(path_to_file).unwrap();
        let mut wasm_binary = wat2wasm(data.clone()).unwrap();

        let data = wat2wasm(&data.clone()).unwrap();
        println!("data len: {}", data.len());
        println!("data raw (hex): {:x?}", data);

        let mut m = Module::decode_from(data.as_slice()).unwrap();
        for s in m.sections.iter_mut() {
            unlazify_with_opt(s, false).unwrap();
            match s.kind() {
                Kind::Type => {
                    println!("---Kind::Type:");
                    let mut bytes = Vec::<u8>::new();
                    s.encode(&mut bytes).unwrap();
                    println!("section len: {:?}", compute_section_len(&bytes));
                    println!("raw (hex): {:x?}", bytes);
                    println!("{:#?}", s);
                }
                Kind::Import => {
                    println!("---Kind::Import:");
                    let mut bytes = Vec::<u8>::new();
                    s.encode(&mut bytes).unwrap();
                    println!("section len: {:?}", compute_section_len(&bytes));
                    println!("raw (hex): {:x?}", bytes);
                    println!("{:#?}", s);
                }
                Kind::Function => {
                    println!("---Kind::Function:");
                    let mut bytes = Vec::<u8>::new();
                    s.encode(&mut bytes).unwrap();
                    println!("section len: {:?}", compute_section_len(&bytes));
                    println!("raw (hex): {:x?}", bytes);
                    println!("{:#?}", s);
                }
                Kind::Code => {
                    println!("---Kind::Code:");
                    let mut bytes = Vec::<u8>::new();
                    s.encode(&mut bytes).unwrap();
                    println!("section len: {:?}", compute_section_len(&bytes));
                    println!("raw (hex): {:x?}", bytes);
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
                Kind::Memory => {
                    println!("---Kind::Memory:");
                    let mut bytes = Vec::<u8>::new();
                    s.encode(&mut bytes).unwrap();
                    println!("section len: {:?}", compute_section_len(&bytes));
                    println!("raw (hex): {:x?}", bytes);
                    println!("{:#?}", s);
                }
                Kind::Export => {
                    println!("---Kind::Export:");
                    let mut bytes = Vec::<u8>::new();
                    s.encode(&mut bytes).unwrap();
                    println!("section len: {:?}", compute_section_len(&bytes));
                    println!("raw (hex): {:x?}", bytes);
                    println!("{:#?}", s);
                }
                Kind::Data => {
                    println!("---Kind::Data:");
                    let mut bytes = Vec::<u8>::new();
                    s.encode(&mut bytes).unwrap();
                    println!("section len: {:?}", compute_section_len(&bytes));
                    println!("raw (hex): {:x?}", bytes);
                    println!("{:#?}", s);
                }
                Kind::Start => {
                    println!("---Kind::Start:");
                    let mut bytes = Vec::<u8>::new();
                    s.encode(&mut bytes).unwrap();
                    println!("section len: {:?}", compute_section_len(&bytes));
                    println!("raw (hex): {:x?}", bytes);
                    println!("{:#?}", s);
                },
                _ => println!("UNKNOWN/UNPROCESSED section kind: {:?}", s.kind()),
            }
        }
        println!("Found {} sections.", m.sections.len());
    }
}