use halo2_proofs::{
    plonk::{ConstraintSystem, Error},
};
use std::{marker::PhantomData};
use std::rc::Rc;
use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner};
use halo2_proofs::plonk::Circuit;
use eth_types::{Field, Hash, ToWord};
use crate::wasm_circuit::leb128_circuit::circuit::LEB128Chip;
use crate::wasm_circuit::bytecode::bytecode::WasmBytecode;
use crate::wasm_circuit::bytecode::bytecode_table::WasmBytecodeTable;
use crate::wasm_circuit::sections::r#type::type_item::circuit::{WasmTypeSectionItemChip};

#[derive(Default)]
struct TestCircuit<'a, F> {
    code_hash: Hash,
    bytecode_bytes: &'a [u8],
    offset_start: usize,
    _marker: PhantomData<F>,
}

#[derive(Clone)]
struct TestCircuitConfig<F> {
    chip: Rc<WasmTypeSectionItemChip<F>>,
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
        // let bytes = cs.advice_column();
        let wasm_bytecode_table = Rc::new(WasmBytecodeTable::construct(cs));
        let leb128_config = LEB128Chip::<F>::configure(
            cs,
            &wasm_bytecode_table.value,
        );
        let leb128_chip = LEB128Chip::construct(leb128_config);
        let wasm_type_section_item_config = WasmTypeSectionItemChip::configure(
            cs,
            wasm_bytecode_table.clone(),
            Rc::new(leb128_chip),
        );
        let wasm_type_section_item_chip = WasmTypeSectionItemChip::construct(wasm_type_section_item_config);
        let test_circuit_config = TestCircuitConfig {
            chip: Rc::new(wasm_type_section_item_chip),
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
        let wasm_bytecode = WasmBytecode::new(self.bytecode_bytes.to_vec().clone(), self.code_hash.to_word());
        config.wasm_bytecode_table.load(&mut layouter, &wasm_bytecode)?;
        layouter.assign_region(
            || "wasm_type_section_item region",
            |mut region| {
                let mut offset_start = self.offset_start;
                while offset_start < wasm_bytecode.bytes.len() {
                    offset_start = config.chip.assign_auto(
                        &mut region,
                        &wasm_bytecode,
                        offset_start,
                    ).unwrap();
                }

                Ok(())
            }
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod wasm_type_section_item_tests {
    use halo2_proofs::dev::MockProver;
    use halo2_proofs::halo2curves::bn256::Fr;
    use log::debug;
    use rand::Rng;
    use bus_mapping::state_db::CodeDB;
    use eth_types::Field;
    use crate::wasm_circuit::consts::NumType;
    use crate::wasm_circuit::sections::r#type::test_helpers::generate_type_section_functype_bytecode;
    use crate::wasm_circuit::sections::r#type::type_item::tests::TestCircuit;

    fn test<'a, F: Field>(
        test_circuit: TestCircuit<'_, F>,
        is_ok: bool,
    ) {
        let k = 5;
        let prover = MockProver::run(k, &test_circuit, vec![]).unwrap();
        if is_ok {
            prover.assert_satisfied();
        } else {
            assert!(prover.verify().is_err());
        }
    }

    #[test]
    pub fn test_type_section_item_bytecode_is_ok() {
        let bytecodes = [
            generate_type_section_functype_bytecode(0, 0),
            generate_type_section_functype_bytecode(0, 1),
            generate_type_section_functype_bytecode(1, 0),
            generate_type_section_functype_bytecode(1, 1),
            generate_type_section_functype_bytecode(1, 2),
            generate_type_section_functype_bytecode(2, 1),
            generate_type_section_functype_bytecode(2, 2),
        ];
        for bytecode in bytecodes {
            let code_hash = CodeDB::hash(&bytecode);
            debug!("bytecode (hex): {:x?}", bytecode);
            let test_circuit = TestCircuit::<Fr> {
                code_hash,
                bytecode_bytes: &bytecode,
                offset_start: 0,
                _marker: Default::default(),
            };
            test(test_circuit, true);
        }
    }

    #[test]
    pub fn test_type_section_item_arg_type_unsupported() {
        let mut rng = rand::thread_rng();
        let arg_type_bytecode_offsets = [2, 3, 5];
        let section_item_bytecode = [0x60, 0x2, 0x7e, 0x7f, 0x1, 0x7f];

        for offset in arg_type_bytecode_offsets {
            let mut section_item_bytecode = section_item_bytecode.clone();
            let mut arg_type_bad_val: u8 = 0;
            loop {
                arg_type_bad_val = rng.gen();
                if arg_type_bad_val != NumType::I32 as u8 && arg_type_bad_val != NumType::I64 as u8 {
                    break
                }
            }
            section_item_bytecode[offset] = arg_type_bad_val;
            let code_hash = CodeDB::hash(&section_item_bytecode);
            let test_circuit = TestCircuit::<Fr> {
                code_hash,
                bytecode_bytes: &section_item_bytecode,
                offset_start: 0,
                _marker: Default::default(),
            };
            test(test_circuit, false);
        }
    }
}