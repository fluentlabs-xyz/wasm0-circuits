use std::env;
use wabt::wat2wasm;
use wasmparser::{Encoding, Parser, Payload, Validator, WasmFeatures};


fn main() {
    let args = env::args().collect::<Vec<_>>();
    if args.len() != 2 {
        println!("Usage: {} in.wasm", args[0]);
        return;
    }

    let wasm_features = WasmFeatures::default();

    let mut validator = Validator::new_with_features(wasm_features.clone());

    let buf: Vec<u8> = std::fs::read(&args[1]).unwrap();
    let buf = wat2wasm(buf).unwrap();
    println!("buf len: {}", buf.len());
    if validator.validate_all(&buf).is_err() {
        println!("file contains invalid wasm binary");
        return;
    }
    for (i, payload) in Parser::new(0).parse_all(&buf).into_iter().enumerate() {
        println!("---payload {}:", i);
        match payload.unwrap() {
            Payload::Version { num, encoding, range } => {
                let encoding_str = match encoding {
                    Encoding::Module => "module",
                    Encoding::Component => "component",
                };
                println!("====== Module Version {} encoding {} range.start={} range.end={}", num, encoding_str, range.start, range.end);
            }
            Payload::ExportSection(reader) => {
                for export in reader {
                    let export = export.unwrap();
                    println!("  ExportSection {} {:?}", export.name, export.kind);
                }
            }
            Payload::ImportSection(reader) => {
                for import in reader {
                    let import = import.unwrap();
                    println!("  ImportSection {}::{}", import.module, import.name);
                }
            }
            Payload::FunctionSection(reader) => {
                for v in reader {
                    let v = v.unwrap();
                    println!("  FunctionSection {}", v);
                }
            }
            Payload::TypeSection(reader) => {
                for v in reader {
                    let v = v.unwrap();
                    println!("  TypeSection");
                }
            }
            Payload::CodeSectionStart { count, range, size } => {
                println!(
                    "  CodeSectionStart count {} range.start {} range.end {} size {}",
                    count,
                    range.start,
                    range.end,
                    size
                );
            }
            Payload::CodeSectionEntry(v) => {
                println!("  CodeSectionEntry range.start {} range.end {}", v.range().start, v.range().end);
                for (i1, mut operators_reader) in v.get_operators_reader().into_iter().enumerate() {
                    println!("  CodeSectionEntry operators_reader", );
                    for operator in operators_reader.read() {
                        println!("  CodeSectionEntry operators_reader operator");
                    }
                }
            }
            _other => {
                println!("UNKNOWN/UNPROCESSED payload: {:?}", _other);
            }
        }
    }
}
