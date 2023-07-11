use halo2_proofs::{
    plonk::{ConstraintSystem, Error},
};
use std::{marker::PhantomData};
use std::cell::RefCell;
use std::rc::Rc;
use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner};
use halo2_proofs::plonk::Circuit;
use eth_types::{Field, Hash, ToWord};
use crate::wasm_circuit::leb128_circuit::circuit::LEB128Chip;
use crate::wasm_circuit::utf8_circuit::circuit::UTF8Chip;
use crate::wasm_circuit::bytecode::bytecode::WasmBytecode;
use crate::wasm_circuit::bytecode::bytecode_table::WasmBytecodeTable;
use crate::wasm_circuit::sections::code::code_body::circuit::WasmCodeSectionBodyChip;
use crate::wasm_circuit::sections::start::start_body::circuit::WasmStartSectionBodyChip;
use crate::wasm_circuit::tables::dynamic_indexes::circuit::DynamicIndexesChip;

#[derive(Default)]
struct TestCircuit<'a, F> {
    code_hash: Hash,
    bytecode: &'a [u8],
    offset_start: usize,
    _marker: PhantomData<F>,
}

#[derive(Clone)]
struct TestCircuitConfig<F: Field> {
    start_section_body_chip: Rc<WasmStartSectionBodyChip<F>>,
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

        let config = WasmStartSectionBodyChip::configure(
            cs,
            wasm_bytecode_table.clone(),
            leb128_chip.clone(),
        );
        let wasm_start_section_body_chip = Rc::new(WasmStartSectionBodyChip::construct(config));

        let test_circuit_config = TestCircuitConfig {
            start_section_body_chip: wasm_start_section_body_chip,
            wasm_bytecode_table,
            _marker: Default::default(),
        };

        test_circuit_config
    }

    fn synthesize(
        &self,
        mut config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let wasm_bytecode = WasmBytecode::new(self.bytecode.to_vec().clone(), self.code_hash.to_word());
        config.wasm_bytecode_table.load(&mut layouter, &wasm_bytecode)?;

        layouter.assign_region(
            || "wasm_start_section_body region",
            |mut region| {
                let mut offset = self.offset_start;
                loop {
                    offset = config.start_section_body_chip.assign_auto(
                        &mut region,
                        &wasm_bytecode,
                        offset,
                    ).unwrap();
                    if offset >= wasm_bytecode.bytes.len() { break }
                }

                Ok(())
            }
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod wasm_start_section_body_tests {
    use halo2_proofs::dev::MockProver;
    use halo2_proofs::halo2curves::bn256::Fr;
    use log::debug;
    use wasmbin::sections::Kind;
    use bus_mapping::state_db::CodeDB;
    use eth_types::Field;
    use crate::wasm_circuit::common::{wat_extract_section_body_bytecode, wat_extract_section_bytecode};
    use crate::wasm_circuit::consts::MemSegmentType;
    use crate::wasm_circuit::sections::start::start_body::tests::TestCircuit;

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
    pub fn section_body_bytecode_ok() {
        let path_to_file = "./src/wasm_circuit/test_data/files/block_loop_local_vars.wat";
        let kind = Kind::Start;
        // expected
        // raw (hex): [8, 1, 2, ]
        let expected = [
            8, 1, 2,
        ].as_slice().to_vec();

        let section_bytecode = wat_extract_section_bytecode(path_to_file, kind, );
        debug!("expected {:?}", expected);
        debug!("section_bytecode {:?}", section_bytecode);
        debug!("");
        debug!("expected (hex) {:x?}", expected);
        debug!("section_bytecode (hex) {:x?}", section_bytecode);
        assert_eq!(expected, section_bytecode);

        let mut start_section_body_bytecode = wat_extract_section_body_bytecode(path_to_file, kind, );
        // expected raw (hex): [2, ]
        debug!("start_section_body_bytecode (len {}) (hex): {:x?}", start_section_body_bytecode.len(), start_section_body_bytecode);
        let code_hash = CodeDB::hash(&start_section_body_bytecode);
        let mut bytecode: Vec<u8> = vec![];
        bytecode.extend(start_section_body_bytecode.iter());
        let test_circuit = TestCircuit::<Fr> {
            code_hash,
            bytecode: &bytecode,
            offset_start: 0,
            _marker: Default::default(),
        };
        test(test_circuit, true);
    }

    #[test]
    pub fn section_body_bytecode_contains_2_leb_args_fail() {
        let path_to_file = "./src/wasm_circuit/test_data/files/block_loop_local_vars.wat";
        let kind = Kind::Start;
        // expected
        // raw (hex): [8, 1, 2, ]
        let expected = [
            8, 1, 2,
        ].as_slice().to_vec();

        let section_bytecode = wat_extract_section_bytecode(path_to_file, kind, );
        debug!("expected {:?}", expected);
        debug!("section_bytecode {:?}", section_bytecode);
        debug!("");
        debug!("expected (hex) {:x?}", expected);
        debug!("section_bytecode (hex) {:x?}", section_bytecode);
        assert_eq!(expected, section_bytecode);

        let mut section_body_bytecode = wat_extract_section_body_bytecode(path_to_file, kind, );
        // expected
        // raw (hex): [2, 2, ]
        section_body_bytecode.extend(section_body_bytecode.clone());
        debug!("section_body_bytecode (len {}) (hex): {:x?}", section_body_bytecode.len(), section_body_bytecode);
        let code_hash = CodeDB::hash(&section_body_bytecode);
        let test_circuit = TestCircuit::<Fr> {
            code_hash,
            bytecode: &section_body_bytecode,
            offset_start: 0,
            _marker: Default::default(),
        };
        test(test_circuit, false);
    }
}