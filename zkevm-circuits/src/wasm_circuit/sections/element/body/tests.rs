use std::{cell::RefCell, marker::PhantomData, rc::Rc};

use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner},
    plonk::{Circuit, ConstraintSystem, Error},
};

use eth_types::{Field, Hash, ToWord};

use crate::wasm_circuit::{
    bytecode::{bytecode::WasmBytecode, bytecode_table::WasmBytecodeTable},
    leb128::circuit::LEB128Chip,
    sections::element::body::circuit::WasmElementSectionBodyChip,
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
    body_chip: Rc<WasmElementSectionBodyChip<F>>,
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
        let wb_table = Rc::new(WasmBytecodeTable::construct(cs, false));
        let func_count = cs.advice_column();
        let error_code = cs.advice_column();
        let body_item_rev_count = cs.advice_column();

        let shared_state = Rc::new(RefCell::new(SharedState::default()));

        let leb128_config = LEB128Chip::<F>::configure(cs, &wb_table.value);
        let leb128_chip = Rc::new(LEB128Chip::construct(leb128_config));

        let wasm_element_section_body_config = WasmElementSectionBodyChip::configure(
            cs,
            wb_table.clone(),
            leb128_chip.clone(),
            func_count,
            shared_state.clone(),
            body_item_rev_count,
            error_code,
        );
        let wasm_element_section_body_chip =
            WasmElementSectionBodyChip::construct(wasm_element_section_body_config);
        let test_circuit_config = TestCircuitConfig {
            body_chip: Rc::new(wasm_element_section_body_chip),
            wb_table: wb_table.clone(),
            _marker: Default::default(),
        };

        test_circuit_config
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let wb = WasmBytecode::new(self.bytecode.to_vec().clone());
        let assign_delta = 0;
        layouter
            .assign_region(
                || format!("wasm bytecode table at {}", assign_delta),
                |mut region| {
                    config.wb_table.load(&mut region, &wb, assign_delta)?;
                    Ok(())
                },
            )
            .unwrap();
        layouter.assign_region(
            || "wasm_element_section_body region",
            |mut region| {
                let mut offset_start = self.offset_start;
                while offset_start < wb.bytes.len() {
                    offset_start = config
                        .body_chip
                        .assign_auto(&mut region, &wb, offset_start, assign_delta)
                        .unwrap();
                }

                Ok(())
            },
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod wasm_element_section_body_tests {
    use halo2_proofs::{dev::MockProver, halo2curves::bn256::Fr};
    use log::debug;
    use wasmbin::sections::Kind;

    use bus_mapping::state_db::CodeDB;
    use eth_types::Field;

    use crate::wasm_circuit::{
        common::{wat_extract_section_body_bytecode, wat_extract_section_bytecode},
        sections::element::body::tests::TestCircuit,
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
    pub fn file2_ok() {
        let path_to_file = "./test_files/cc2.wat";
        let kind = Kind::Element;
        let expected = [
            9, 35, 7, 1, 0, 0, 1, 0, 0, 1, 0, 3, 0, 0, 1, 1, 0, 4, 0, 0, 1, 1, 1, 0, 0, 0, 65, 0,
            11, 0, 0, 65, 171, 2, 11, 1, 0,
        ]
        .as_slice()
        .to_vec();
        debug!("expected {:?}", expected);
        debug!("expected (hex) {:x?}", expected);

        let section_bytecode = wat_extract_section_bytecode(path_to_file, kind);
        debug!("section_bytecode {:?}", section_bytecode);
        debug!("section_bytecode (hex) {:x?}", section_bytecode);
        assert_eq!(expected, section_bytecode);

        let expected = [
            7, 1, 0, 0, 1, 0, 0, 1, 0, 3, 0, 0, 1, 1, 0, 4, 0, 0, 1, 1, 1, 0, 0, 0, 65, 0, 11, 0,
            0, 65, 171, 2, 11, 1, 0,
        ]
        .as_slice()
        .to_vec();
        let section_body_bytecode = wat_extract_section_body_bytecode(path_to_file, kind);
        assert_eq!(expected, section_body_bytecode);

        debug!(
            "section_body_bytecode (len {}) (hex): {:x?}",
            section_body_bytecode.len(),
            section_body_bytecode
        );
        let code_hash = CodeDB::hash(&section_body_bytecode);
        let test_circuit = TestCircuit::<Fr> {
            code_hash,
            bytecode: &section_body_bytecode,
            offset_start: 0,
            _marker: Default::default(),
        };
        test(test_circuit, true);
    }
}
