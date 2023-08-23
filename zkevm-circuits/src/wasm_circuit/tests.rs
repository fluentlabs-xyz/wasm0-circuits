use std::{cell::RefCell, marker::PhantomData, rc::Rc};

use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner},
    plonk::{Circuit, ConstraintSystem, Error},
};
use log::debug;

use eth_types::{Field, ToWord};

use crate::wasm_circuit::{
    bytecode::{bytecode::WasmBytecode, bytecode_table::WasmBytecodeTable},
    circuit::{WasmChip, WasmConfig},
    types::SharedState,
};

#[derive(Default)]
struct TestCircuitWithErrorProcessing<F> {
    wbs: Vec<WasmBytecode>,
    wb_offset: usize,
    _marker: PhantomData<F>,
}

impl<F: Field> Circuit<F> for TestCircuitWithErrorProcessing<F> {
    type Config = WasmConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(cs: &mut ConstraintSystem<F>) -> Self::Config {
        let mut shared_state = Rc::new(RefCell::new(SharedState::default()));
        shared_state.borrow_mut().error_processing_enabled = true;
        let wb_table = WasmBytecodeTable::construct(cs, true);
        let config = WasmChip::<F>::configure(cs, Rc::new(wb_table), shared_state);

        config
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let mut wasm_chip = WasmChip::construct(config);

        let mut assign_delta = 0;
        for wb in &self.wbs {
            wasm_chip.load(&mut layouter, &wb, assign_delta).unwrap();
        }

        layouter.assign_region(
            || "wasm_chip region",
            |mut region| {
                wasm_chip.config.shared_state.borrow_mut().reset();
                let mut assign_delta = 0;
                for wb in &self.wbs {
                    assign_delta = wasm_chip
                        .assign_auto(&mut region, &wb, self.wb_offset, assign_delta)
                        .unwrap();
                    // debug!(
                    //     "RESULT error_code {}",
                    //     wasm_chip.config.shared_state.borrow().error_code
                    // );
                }

                Ok(assign_delta)
            },
        )?;

        Ok(())
    }
}

#[derive(Default)]
struct TestCircuit<F> {
    wbs: Vec<WasmBytecode>,
    wb_offset: usize,
    _marker: PhantomData<F>,
}

impl<F: Field> Circuit<F> for TestCircuit<F> {
    type Config = WasmConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(cs: &mut ConstraintSystem<F>) -> Self::Config {
        let shared_state = Rc::new(RefCell::new(SharedState::default()));
        let wb_table = WasmBytecodeTable::construct(cs, true);
        let config = WasmChip::<F>::configure(cs, Rc::new(wb_table), shared_state);

        config
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let mut wasm_chip = WasmChip::construct(config);

        let mut assign_delta = 0;
        for wb in &self.wbs {
            wasm_chip.load(&mut layouter, &wb, assign_delta).unwrap();
        }

        layouter.assign_region(
            || "wasm_chip region",
            |mut region| {
                wasm_chip.config.shared_state.borrow_mut().reset();
                let mut assign_delta = 0;
                for wb in &self.wbs {
                    assign_delta = wasm_chip
                        .assign_auto(&mut region, &wb, self.wb_offset, assign_delta)
                        .unwrap();
                    debug!(
                        "RESULT error_code {}",
                        wasm_chip.config.shared_state.borrow().error_code
                    );
                }

                Ok(assign_delta)
            },
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod wasm_circuit_tests {
    use ethers_core::k256::pkcs8::der::Encode;
    use halo2_proofs::{dev::MockProver, halo2curves::bn256::Fr};
    use log::debug;
    use rand::{random, thread_rng, Rng};
    use wabt::wat2wasm;

    use eth_types::Field;

    use crate::wasm_circuit::{
        bytecode::bytecode::WasmBytecode,
        consts::{
            WASM_MAGIC_PREFIX_END_INDEX, WASM_MAGIC_PREFIX_LEN, WASM_MAGIC_PREFIX_START_INDEX,
            WASM_VERSION_PREFIX_END_INDEX, WASM_VERSION_PREFIX_LEN,
            WASM_VERSION_PREFIX_START_INDEX,
        },
        tests::{TestCircuit, TestCircuitWithErrorProcessing},
        tests_helpers::mutate_byte,
        types::WasmSection,
    };

    fn test_no_error_processing<'a, F: Field>(test_circuit: &TestCircuit<F>, is_ok: bool) {
        let k = 10;
        let prover = MockProver::run(k, test_circuit, vec![]).unwrap();
        if is_ok {
            prover.assert_satisfied();
        } else {
            assert!(prover.verify().is_err());
        }
    }

    fn debug_wb(wb: &WasmBytecode) {
        debug!("wb.len: {}", wb.bytes.len());
        debug!("wb.len hex: {:x?}", wb.bytes.len());
        debug!("wb last_index: {}", wb.bytes.len() - 1);
        debug!("wb last_index hex: {:x?}", wb.bytes.len() - 1);
        debug!("wb: {:x?}", wb.bytes);
    }

    fn test_with_error_processing<'a, F: Field>(
        test_circuit: &TestCircuitWithErrorProcessing<F>,
        is_ok: bool,
    ) {
        let k = 10;
        let prover = MockProver::run(k, test_circuit, vec![]).unwrap();
        if is_ok {
            prover.assert_satisfied();
        } else {
            assert!(prover.verify().is_err());
        }
    }

    #[test]
    pub fn file1_ok() {
        let path_to_file = "./test_files/cc1.wat";
        let data: Vec<u8> = std::fs::read(path_to_file).unwrap();
        let bytes = wat2wasm(data).unwrap();
        let mut wb = WasmBytecode::new(bytes);
        debug_wb(&wb);
        let circuit = TestCircuit::<Fr> {
            wbs: vec![wb],
            ..Default::default()
        };
        test_no_error_processing(&circuit, true);
    }

    #[test]
    pub fn file2_ok() {
        let path_to_file = "./test_files/cc2.wat";
        let data: Vec<u8> = std::fs::read(path_to_file).unwrap();
        let bytes = wat2wasm(data).unwrap();
        let wb = WasmBytecode::new(bytes);
        debug_wb(&wb);
        let circuit = TestCircuit::<Fr> {
            wbs: vec![wb],
            ..Default::default()
        };
        test_no_error_processing(&circuit, true);
    }

    #[test]
    pub fn file3_ok() {
        let path_to_file = "./test_files/cc3.wat";
        let data: Vec<u8> = std::fs::read(path_to_file).unwrap();
        let bytes = wat2wasm(data).unwrap();
        let wb = WasmBytecode::new(bytes);
        debug_wb(&wb);
        let circuit = TestCircuit::<Fr> {
            wbs: vec![wb],
            ..Default::default()
        };
        test_no_error_processing(&circuit, true);
    }

    #[test]
    pub fn invalid_bytecode_error_processing() {
        let paths_to_files = [
            "./test_files/cc1.wat",
            "./test_files/cc2.wat",
            "./test_files/cc3.wat",
        ];
        for path_to_file in paths_to_files {
            let data: Vec<u8> = std::fs::read(path_to_file).unwrap();
            let bytes = wat2wasm(data).unwrap();
            let mut wb = WasmBytecode::new(bytes);
            let i: usize = random::<usize>() % WASM_MAGIC_PREFIX_LEN;
            mutate_byte(&mut wb.bytes[i]);
            let circuit = TestCircuitWithErrorProcessing::<Fr> {
                wbs: vec![wb],
                ..Default::default()
            };
            test_with_error_processing(&circuit, true);
        }
    }

    #[test]
    pub fn bad_magic_prefix_parse_error() {
        let paths_to_files = [
            "./test_files/cc1.wat",
            "./test_files/cc2.wat",
            "./test_files/cc3.wat",
        ];
        for path_to_file in paths_to_files {
            let data: Vec<u8> = std::fs::read(path_to_file).unwrap();
            let bytes = wat2wasm(data).unwrap();
            let mut wb = WasmBytecode::new(bytes);
            let i: usize = random::<usize>() % WASM_MAGIC_PREFIX_LEN;
            mutate_byte(&mut wb.bytes[i]);
            let circuit = TestCircuitWithErrorProcessing::<Fr> {
                wbs: vec![wb],
                ..Default::default()
            };
            test_with_error_processing(&circuit, true);
        }
    }

    #[test]
    pub fn bad_version_parse_error() {
        let paths_to_files = [
            "./test_files/cc1.wat",
            "./test_files/cc2.wat",
            "./test_files/cc3.wat",
        ];
        for path_to_file in paths_to_files {
            println!("processing file '{}'", path_to_file);
            let data: Vec<u8> = std::fs::read(path_to_file).unwrap();
            let bytes = wat2wasm(data).unwrap();
            let mut wb = WasmBytecode::new(bytes);
            let i: usize =
                WASM_VERSION_PREFIX_START_INDEX + random::<usize>() % WASM_VERSION_PREFIX_LEN;
            mutate_byte(&mut wb.bytes[i]);
            let circuit = TestCircuitWithErrorProcessing::<Fr> {
                wbs: vec![wb],
                ..Default::default()
            };
            test_with_error_processing(&circuit, true);
        }
    }

    #[ignore] // TODO some problems after new module integration
    #[test]
    pub fn test_random_bytecode_must_fail() {
        let bytes: Vec<u8> = [0, 1, 2, 3].to_vec().unwrap();
        let wb = WasmBytecode::new(bytes);
        let circuit = TestCircuitWithErrorProcessing::<Fr> {
            wbs: vec![wb],
            ..Default::default()
        };
        test_with_error_processing(&circuit, false);
    }

    #[test]
    pub fn file1_invalid_magic_prefix_parse_error() {
        let path_to_file = "./test_files/cc1.wat";
        let data: Vec<u8> = std::fs::read(path_to_file).unwrap();
        let bytes = wat2wasm(data).unwrap();
        let mut wb = WasmBytecode::new(bytes);
        debug_wb(&wb);

        // mutate some data
        let idx: usize =
            thread_rng().gen_range(WASM_MAGIC_PREFIX_START_INDEX..=WASM_MAGIC_PREFIX_END_INDEX);
        mutate_byte(&mut wb.bytes[idx]);

        debug!("wb (modified): {:x?}", wb.bytes);
        let circuit = TestCircuitWithErrorProcessing::<Fr> {
            wbs: vec![wb],
            ..Default::default()
        };
        test_with_error_processing(&circuit, true);
    }

    #[test]
    pub fn file1_invalid_version_parse_error() {
        let path_to_file = "./test_files/cc1.wat";
        let data: Vec<u8> = std::fs::read(path_to_file).unwrap();
        let bytes = wat2wasm(data).unwrap();
        let mut wb = WasmBytecode::new(bytes);
        debug_wb(&wb);

        // mutate some data
        let idx: usize =
            thread_rng().gen_range(WASM_VERSION_PREFIX_START_INDEX..=WASM_VERSION_PREFIX_END_INDEX);
        mutate_byte(&mut wb.bytes[idx]);

        debug!("wb (modified): {:x?}", wb.bytes);
        let circuit = TestCircuitWithErrorProcessing::<Fr> {
            wbs: vec![wb],
            ..Default::default()
        };
        test_with_error_processing(&circuit, true);
    }

    #[test]
    pub fn file1_invalid_section_id_parse_error() {
        let path_to_file = "./test_files/cc1.wat";
        let data: Vec<u8> = std::fs::read(path_to_file).unwrap();
        let bytes = wat2wasm(data).unwrap();
        let mut wb = WasmBytecode::new(bytes);
        debug_wb(&wb);

        // change section ID to some unknown
        wb.bytes[8] = thread_rng().gen_range((WasmSection::DataCount as u8 + 1)..255);

        debug!("wb (modified): {:x?}", wb.bytes);
        let circuit = TestCircuitWithErrorProcessing::<Fr> {
            wbs: vec![wb],
            ..Default::default()
        };
        test_with_error_processing(&circuit, true);
    }

    // #[test]
    // pub fn multiple_bytecodes_assignment_ok() {
    //     let paths_to_files = [
    //         "./test_files/cc1.wat",
    //         "./test_files/cc2.wat",
    //         "./test_files/cc3.wat",
    //     ];
    //     for path_to_file in paths_to_files {
    //         println!("processing file '{}'", path_to_file);
    //         let data: Vec<u8> = std::fs::read(path_to_file).unwrap();
    //         let mut wb = wat2wasm(data).unwrap();
    //     }
    //     let circuit = TestCircuitWithErrorProcessing::<Fr> {
    //         wbs: wb.clone(),
    //         code_hash: CodeDB::hash(&wb),
    //         ..Default::default()
    //     };
    //     test_no_error_processing(&circuit, true);
    // }
}
