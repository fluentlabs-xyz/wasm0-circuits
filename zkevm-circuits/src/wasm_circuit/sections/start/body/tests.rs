use std::{cell::RefCell, marker::PhantomData, rc::Rc};

use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner},
    plonk::{Circuit, ConstraintSystem, Error},
};

use eth_types::{Field, Hash, ToWord};

use crate::wasm_circuit::{
    bytecode::{bytecode::WasmBytecode, bytecode_table::WasmBytecodeTable},
    leb128::circuit::LEB128Chip,
    sections::start::body::circuit::WasmStartSectionBodyChip,
    types::SharedState,
};

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
    wb_table: Rc<WasmBytecodeTable>,
    _marker: PhantomData<F>,
}

impl<'a, F: Field> Circuit<F> for TestCircuit<'a, F> {
    type Config = TestCircuitConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(cs: &mut ConstraintSystem<F>) -> Self::Config {
        let wb_table = Rc::new(WasmBytecodeTable::construct(cs));
        let func_count = cs.advice_column();
        let error_code = cs.advice_column();

        let shared_state = Rc::new(RefCell::new(SharedState::default()));

        let leb128_config = LEB128Chip::<F>::configure(cs, &wb_table.value);
        let leb128_chip = Rc::new(LEB128Chip::construct(leb128_config));

        let config = WasmStartSectionBodyChip::configure(
            cs,
            wb_table.clone(),
            leb128_chip.clone(),
            func_count,
            shared_state.clone(),
            error_code,
        );
        let wasm_start_section_body_chip = Rc::new(WasmStartSectionBodyChip::construct(config));

        let test_circuit_config = TestCircuitConfig {
            start_section_body_chip: wasm_start_section_body_chip,
            wb_table,
            _marker: Default::default(),
        };

        test_circuit_config
    }

    fn synthesize(
        &self,
        mut config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let wb = WasmBytecode::new(self.bytecode.to_vec().clone(), self.code_hash.to_word());
        config.wb_table.load(&mut layouter, &wb, false, 0)?;

        layouter.assign_region(
            || "wasm_start_section_body region",
            |mut region| {
                let mut offset_start = self.offset_start;
                while offset_start < wb.bytes.len() {
                    offset_start = config
                        .start_section_body_chip
                        .assign_auto(&mut region, &wb, offset_start, 0)
                        .unwrap();
                }

                Ok(())
            },
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod wasm_start_section_body_tests {
    use halo2_proofs::{dev::MockProver, halo2curves::bn256::Fr};
    use log::debug;
    use wasmbin::sections::Kind;

    use bus_mapping::state_db::CodeDB;
    use eth_types::Field;

    use crate::wasm_circuit::{
        common::{wat_extract_section_body_bytecode, wat_extract_section_bytecode},
        sections::start::body::tests::TestCircuit,
    };

    fn test<'a, F: Field>(test_circuit: TestCircuit<'_, F>, is_ok: bool) {
        let k = 8;
        let prover = MockProver::run(k, &test_circuit, vec![]).unwrap();
        if is_ok {
            prover.assert_satisfied();
        } else {
            assert!(prover.verify().is_err());
        }
    }

    #[test]
    pub fn file2_dup_fails() {
        let path_to_file = "./test_files/cc2.wat";
        let kind = Kind::Start;

        let mut bytecode = wat_extract_section_body_bytecode(path_to_file, kind);
        bytecode.extend(bytecode.clone());
        debug!(
            "bytecode len {} hex {:x?} bin {:?}",
            bytecode.len(),
            bytecode,
            bytecode
        );
        let code_hash = CodeDB::hash(&bytecode);
        let test_circuit = TestCircuit::<Fr> {
            code_hash,
            bytecode: &bytecode,
            offset_start: 0,
            _marker: Default::default(),
        };
        test(test_circuit, false);
    }

    #[test]
    pub fn file1_ok() {
        let path_to_file = "./test_files/cc1.wat";
        let kind = Kind::Start;

        let section_bytecode = wat_extract_section_bytecode(path_to_file, kind);
        debug!("section_bytecode {:?}", section_bytecode);
        debug!("section_bytecode (hex) {:x?}", section_bytecode);

        let mut bytecode = wat_extract_section_body_bytecode(path_to_file, kind);
        debug!(
            "bytecode len {} hex {:x?} bin {:?}",
            bytecode.len(),
            bytecode,
            bytecode
        );
        let code_hash = CodeDB::hash(&bytecode);
        let test_circuit = TestCircuit::<Fr> {
            code_hash,
            bytecode: &bytecode,
            offset_start: 0,
            _marker: Default::default(),
        };
        test(test_circuit, true);
    }

    #[test]
    pub fn file2_ok() {
        let path_to_file = "./test_files/cc2.wat";
        let kind = Kind::Start;
        let expected = [8, 1, 2].as_slice().to_vec();

        let section_bytecode = wat_extract_section_bytecode(path_to_file, kind);
        debug!("expected {:?}", expected);
        debug!("section_bytecode {:?}", section_bytecode);
        debug!("");
        debug!("expected (hex) {:x?}", expected);
        debug!("section_bytecode (hex) {:x?}", section_bytecode);
        assert_eq!(expected, section_bytecode);

        let mut bytecode = wat_extract_section_body_bytecode(path_to_file, kind);
        debug!(
            "bytecode len {} hex {:x?} bin {:?}",
            bytecode.len(),
            bytecode,
            bytecode
        );
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
