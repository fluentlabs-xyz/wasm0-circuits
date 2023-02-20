use std::path::PathBuf;
use crate::wasm_circuit::{
    circuits::{config::zkwasm_k, TestCircuit},
};

use halo2_proofs::{dev::MockProver};
use crate::wasm_circuit::specs::Tables;
use halo2_proofs::plonk::Error;
use eth_types::Field;

mod spec;
mod selfbalance;

pub fn test_circuit_noexternal(textual_repr: &str) -> Result<(), ()> {
    panic!("not implemented: {}", textual_repr)
    // let wasm = wabt::wat2wasm(&textual_repr).expect("failed to parse wat");
    //
    // let compiler = WasmInterpreter::new();
    // let compiled_module = compiler
    //     .compile(&wasm, &ImportsBuilder::default(), &HashMap::default())
    //     .unwrap();
    // let execution_result = compiled_module.run(&mut NopExternals, "test")?;
    //
    // run_test_circuit::<Fp>(execution_result.tables, vec![])
}

pub fn run_test_circuit<F: Field>(tables: Tables, public_inputs: Vec<F>, path_buf: Option<PathBuf>) -> Result<(), Error> {
    tables.write_json(path_buf);

    let circuit = TestCircuit::<F>::new(tables);

    let prover = MockProver::run(zkwasm_k(), &circuit, vec![public_inputs])?;
    assert_eq!(prover.verify(), Ok(()));

    Ok(())
}
