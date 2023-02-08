use std::io::{Error, Read};
use wasmparser_nostd::{BinaryReader, Chunk, LocalsReader, Parser, Payload, Payload::*};
use nano_leb128::ULEB128;

#[derive(Default, Debug)]
struct WasmParser {
    function_counter: u32,
}

impl WasmParser {

    fn parse_clang_debug_info(&mut self, mut buf: &[u8], debug_names: &mut Vec<String>) {
        // read type
        let (typ, len) = ULEB128::read_from(buf).unwrap();
        if u64::from(typ) != 0x01 {
            todo!("not supported name type: {}", u64::from(typ));
        }
        buf = &buf[len..];
        // skip something
        let (_, len) = ULEB128::read_from(buf).unwrap();
        buf = &buf[len..];
        // read debug symbol count
        let (mut count, len) = ULEB128::read_from(buf).unwrap();
        buf = &buf[len..];

        for _ in 0..u64::from(count) {
            let (_, len) = ULEB128::read_from(buf).unwrap();
            buf = &buf[len..];
            let (length, len) = ULEB128::read_from(buf).unwrap();
            let length = u64::from(length) as usize;
            buf = &buf[len..];
            let name = if length <= buf.len() {
                std::str::from_utf8(&buf[..length]).unwrap()
            } else {
                std::str::from_utf8(buf).unwrap()
            };
            buf = &buf[length..];
            debug_names.push(String::from(name));
        }
    }

    fn handle_wasm_payload(&mut self, payload: &mut Payload) -> Result<(), Error> {
        match payload {
            // Sections for WebAssembly modules
            Version { num, encoding, range } => {
                println!("Version: (num={}, encoding={:?}, range={:?})", num, encoding, range);
            }
            TypeSection(_) => { /* ... */ }
            ImportSection(_) => { /* ... */ }
            FunctionSection(_) => { /* ... */ }
            TableSection(_) => { /* ... */ }
            MemorySection(_) => { /* ... */ }
            TagSection(_) => { /* ... */ }
            GlobalSection(reader) => {
                let mut global_counter = 0;
                while !reader.eof() {
                    let global = reader.read().expect("can't read global variable");
                    let binary_reader = global.init_expr.get_binary_reader();
                    // backend.global_variable(global_counter, binary_reader);
                    global_counter += 1;
                }
            }
            ExportSection(_) => { /* ... */ }
            StartSection { .. } => { /* ... */ }
            ElementSection(_) => { /* ... */ }
            DataCountSection { .. } => { /* ... */ }
            DataSection(_) => { /* ... */ }

            // Here we know how many functions we'll be receiving as
            // `CodeSectionEntry`, so we can prepare for that, and
            // afterwards we can parse and handle each function
            // individually.
            CodeSectionStart { .. } => { /* ... */ }
            CodeSectionEntry(body) => {
                let instructions = body.get_operators_reader().expect("no instructions");
                let locals = body.get_locals_reader().expect("no locals");
                let fn_name = format!("fn_{}", self.function_counter);
                self.function_counter += 1;
                // backend.build_function(fn_name.clone(), instructions.get_binary_reader(), Some(locals));
            }

            // Sections for WebAssembly components
            ModuleSection { .. } => { /* ... */ }
            InstanceSection(_) => { /* ... */ }
            CoreTypeSection(_) => { /* ... */ }
            ComponentSection { .. } => { /* ... */ }
            ComponentInstanceSection(_) => { /* ... */ }
            ComponentAliasSection(_) => { /* ... */ }
            ComponentTypeSection(_) => { /* ... */ }
            ComponentCanonicalSection(_) => { /* ... */ }
            ComponentStartSection { .. } => { /* ... */ }
            ComponentImportSection(_) => { /* ... */ }
            ComponentExportSection(_) => { /* ... */ }

            CustomSection(reader) => {
                match reader.name() {
                    "dylink" => {}
                    "name" => {
                        let mut debug_names: Vec<String> = Vec::new();
                        self.parse_clang_debug_info(reader.data().clone(), &mut debug_names);
                        // backend.rename_functions(debug_names.iter().map(|v| v.as_str()).collect());
                    }
                    "linkking" => {}
                    "producers" => {}
                    "reloc." => {}
                    _ => {}
                }
            }

            // most likely you'd return an error here
            UnknownSection { id, .. } => {
                panic!("unknown section: {}", id);
            }

            // Once we've reached the end of a parser we either resume
            // at the parent parser or we break out of the loop because
            // we're done.
            End(_) => {}
        }
        return Ok(());
    }

    fn extract_wasm_payloads(&mut self, mut reader: impl Read) -> Result<(), Error> {
        let mut parser = Parser::new(0);
        let mut buf = Vec::new();
        let mut eof = false;
        while !eof {
            let (mut payload, consumed) = match parser.parse(&buf, eof).expect("failed to parse wasm body")
            {
                Chunk::NeedMoreData(hint) => {
                    assert!(!eof);
                    let len = buf.len();
                    buf.extend((0..hint).map(|_| 0u8));
                    let n = reader.read(&mut buf[len..])?;
                    buf.truncate(len + n);
                    eof = n == 0;
                    continue;
                }
                Chunk::Parsed { consumed, payload } => (payload, consumed),
            };
            self.handle_wasm_payload(&mut payload)?;
            match payload {
                End(_) => break,
                _ => {}
            }
            buf.drain(..consumed);
        }
        return Ok(());
    }
}

pub fn parse_wasm_body(mut reader: impl Read) -> Result<(), Error> {
    let mut wasm_parser = WasmParser::default();
    wasm_parser.extract_wasm_payloads(reader)?;
    return Ok(());
}
