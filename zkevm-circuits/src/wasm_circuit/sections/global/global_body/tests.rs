use halo2_proofs::{
    plonk::{ConstraintSystem, Error},
};
use std::{marker::PhantomData};
use std::rc::Rc;
use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner};
use halo2_proofs::plonk::Circuit;
use eth_types::{Field, Hash, ToWord};
use crate::wasm_circuit::leb128_circuit::circuit::LEB128Chip;
use crate::wasm_circuit::utf8_circuit::circuit::UTF8Chip;
use crate::wasm_circuit::bytecode::bytecode::WasmBytecode;
use crate::wasm_circuit::bytecode::bytecode_table::WasmBytecodeTable;
use crate::wasm_circuit::sections::global::global_body::circuit::WasmGlobalSectionBodyChip;

#[derive(Default)]
struct TestCircuit<'a, F> {
    code_hash: Hash,
    bytecode: &'a [u8],
    offset_start: usize,
    _marker: PhantomData<F>,
}

#[derive(Clone)]
struct TestCircuitConfig<F: Field> {
    body_chip: Rc<WasmGlobalSectionBodyChip<F>>,
    wasm_bytecode_table: Rc<WasmBytecodeTable>,
    _marker: PhantomData<F>,
}

impl<'a, F: Field> Circuit<F> for TestCircuit<'a, F> {
    type Config = TestCircuitConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self { Self::default() }

    fn configure(
        cs: &mut ConstraintSystem<F>,
    ) -> Self::Config {
        let wasm_bytecode_table = Rc::new(WasmBytecodeTable::construct(cs));

        let leb128_config = LEB128Chip::<F>::configure(
            cs,
            &wasm_bytecode_table.value,
        );
        let leb128_chip = Rc::new(LEB128Chip::construct(leb128_config));

        let wasm_global_section_body_config = WasmGlobalSectionBodyChip::configure(
            cs,
            wasm_bytecode_table.clone(),
            leb128_chip.clone(),
        );
        let wasm_global_section_body_chip = WasmGlobalSectionBodyChip::construct(wasm_global_section_body_config);
        let test_circuit_config = TestCircuitConfig {
            body_chip: Rc::new(wasm_global_section_body_chip),
            wasm_bytecode_table: wasm_bytecode_table.clone(),
            _marker: Default::default(),
        };

        test_circuit_config
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let wasm_bytecode = WasmBytecode::new(self.bytecode.to_vec().clone(), self.code_hash.to_word());
        config.wasm_bytecode_table.load(&mut layouter, &wasm_bytecode)?;
        layouter.assign_region(
            || "wasm_global_section_body region",
            |mut region| {
                let mut offset_start = self.offset_start;
                loop {
                    offset_start = config.body_chip.assign_auto(
                        &mut region,
                        &wasm_bytecode,
                        offset_start,
                    ).unwrap();
                    if offset_start > wasm_bytecode.bytes.len() - 1 { break }
                }

                Ok(())
            }
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod wasm_global_section_body_tests {
    use halo2_proofs::dev::MockProver;
    use halo2_proofs::halo2curves::bn256::Fr;
    use log::debug;
    use bus_mapping::state_db::CodeDB;
    use eth_types::Field;
    use crate::wasm_circuit::consts::NumType;
    use crate::wasm_circuit::sections::global::test_helpers::{generate_wasm_global_section_body_bytecode, WasmGlobalSectionBodyDescriptor, WasmGlobalSectionBodyItemDescriptor};
    use crate::wasm_circuit::sections::global::global_body::tests::TestCircuit;

    fn test<'a, F: Field>(
        test_circuit: TestCircuit<'_, F>,
        is_ok: bool,
    ) {
        let k = 8;
        let prover = MockProver::run(k, &test_circuit, vec![]).unwrap();
        if is_ok {
            prover.assert_satisfied();
        } else {
            assert!(prover.verify().is_err());
        }
    }

    #[test]
    pub fn section_body_bytecode_is_ok() {
        let mut bytecodes: Vec<Vec<u8>> = Vec::new();
        // example (hex, first two bytes are section_id(10=0xA) and section_leb_len):
        // raw (hex): [6, 12, 3, 7f, 1, 41, 0, b, 7e, 1, 42, 0, b, 7e, 1, 42, d1, df, 4, b]
        // raw (decimal): [6, 18, 3, 127, 1, 65, 0, 11, 126, 1, 66, 0, 11, 126, 1, 66, 209, 223, 4, 11]
        let descriptor = WasmGlobalSectionBodyDescriptor {
            funcs: vec![
                WasmGlobalSectionBodyItemDescriptor {
                    global_type: NumType::I32,
                    is_mut: true,
                    init_val: 0,
                },
                WasmGlobalSectionBodyItemDescriptor {
                    global_type: NumType::I64,
                    is_mut: true,
                    init_val: 0,
                },
                WasmGlobalSectionBodyItemDescriptor {
                    global_type: NumType::I64,
                    is_mut: true,
                    init_val: 77777,
                },
            ],
        };
        let bytecode = generate_wasm_global_section_body_bytecode(&descriptor);
        debug!("bytecode (len {}) (hex): {:x?}", bytecode.len(), bytecode);
        bytecodes.push(bytecode);
        for bytecode in &bytecodes {
            let code_hash = CodeDB::hash(&bytecode);
            let test_circuit = TestCircuit::<Fr> {
                code_hash,
                bytecode: &bytecode,
                offset_start: 0,
                _marker: Default::default(),
            };
            test(test_circuit, true);
        }
    }
}