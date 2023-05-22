extern crate core;

use anyhow::{Context, Result};
use std::env;
use wabt::wat2wasm;
use wasmbin::io::{DecodeError, Encode};
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

#[cfg(test)]
mod tests {
    #[test]
    pub fn test_wasmbin() {
        let args = env::args().collect::<Vec<_>>();
        if args.len() != 2 {
            println!("Usage: {} in.wasm", args[0]);
            return Ok(());
        }

        let buf: Vec<u8> = std::fs::read(&args[1]).unwrap();
        let buf = wat2wasm(buf).unwrap();
        println!("buf len: {}", buf.len());
        println!("buf raw: {:?}", buf);

        let mut m = Module::decode_from(buf.as_slice()).with_context(|| {
            format!("Parsing error")
        })?;
        for s in m.sections.iter_mut() {
            unlazify_with_opt(s, false)?;
            match s.kind() {
                Kind::Type => {
                    println!("---Kind::Type:");
                    let mut bytes = Vec::<u8>::new();
                    s.encode(&mut bytes).unwrap();
                    println!("raw: {:?}", bytes);
                    println!("{:#?}", s);
                }
                // Kind::Function => {
                //     println!("---Kind::Function:");
                //     let mut bytes = Vec::<u8>::new();
                //     s.encode(&mut bytes).unwrap();
                //     println!("raw: {:?}", bytes);
                //     println!("{:#?}", s);
                // }
                Kind::Code => {
                    println!("---Kind::Code:");
                    let mut bytes = Vec::<u8>::new();
                    s.encode(&mut bytes).unwrap();
                    println!("raw: {:?}", bytes);
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
                // Kind::Memory => {
                //     println!("---Kind::Memory:");
                //     let mut bytes = Vec::<u8>::new();
                //     s.encode(&mut bytes).unwrap();
                //     println!("raw: {:?}", bytes);
                //     println!("{:#?}", s);
                // }
                // Kind::Export => {
                //     println!("---Kind::Export:");
                //     let mut bytes = Vec::<u8>::new();
                //     s.encode(&mut bytes).unwrap();
                //     println!("raw: {:?}", bytes);
                //     println!("{:#?}", s);
                // }
                // Kind::Data => {
                //     println!("---Kind::Data:");
                //     let mut bytes = Vec::<u8>::new();
                //     s.encode(&mut bytes).unwrap();
                //     println!("raw: {:?}", bytes);
                //     println!("{:#?}", s);
                // }
                Kind::Start => {
                    println!("---Kind::Start:");
                    let mut bytes = Vec::<u8>::new();
                    s.encode(&mut bytes).unwrap();
                    println!("raw: {:?}", bytes);
                    println!("{:#?}", s);
                },
                _ => println!("UNKNOWN/UNPROCESSED section kind: {:?}", s.kind()),
            }
        }
        println!("Found {} sections.", m.sections.len());
        Ok(())
    }
}
