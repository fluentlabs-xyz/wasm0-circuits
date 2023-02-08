use anyhow::Error;
use eth_types::GethExecTrace;
use specs::Tables;
use wasmi::ImportsBuilder;

use crate::runtime::{WasmInterpreter, WasmRuntime};
use crate::runtime::host::HostEnv;
use crate::runtime::wasmi_interpreter::{Execution, WasmiRuntime};

mod runtime;

pub fn extract_wasm_trace(wasm_binary: &Vec<u8>) -> Result<Tables, Error> {
    let compiler = WasmInterpreter::new();

    let mut env = HostEnv::new();
    let imports = ImportsBuilder::new().with_resolver("env", &env);

    let compiled_module = compiler
        .compile(&wasm_binary, &imports, &env.function_plugin_lookup)
        .unwrap();
    let execution_result = compiled_module.run(&mut env, "main")?;

    Ok(execution_result.tables)
}
