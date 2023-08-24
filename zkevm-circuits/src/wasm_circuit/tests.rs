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
    assign_delta_base: usize,
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
        let wb_table = Rc::new(WasmBytecodeTable::construct(cs, true));
        let config = WasmChip::<F>::configure(cs, wb_table, shared_state);

        config
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let mut wasm_chip = WasmChip::construct(config);

        wasm_chip.load_once(&mut layouter).unwrap();

        layouter.assign_region(
            || "wasm_chip region",
            |mut region| {
                wasm_chip.config.shared_state.borrow_mut().reset();
                let mut assign_delta = self.assign_delta_base;
                for wb in &self.wbs {
                    wasm_chip.load(&mut region, wb, assign_delta).unwrap();
                    assign_delta = wasm_chip
                        .assign_auto(&mut region, wb, self.wb_offset, assign_delta)
                        .unwrap();
                    // debug!(
                    //     "RESULT error_code {}",
                    //     wasm_chip.config.shared_state.borrow().error_code
                    // );
                }

                Ok(())
            },
        )?;

        Ok(())
    }
}

#[derive(Default)]
struct TestCircuit<F> {
    wbs: Vec<WasmBytecode>,
    wb_offset: usize,
    assign_delta_base: usize,
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
        let wb_table = Rc::new(WasmBytecodeTable::construct(cs, true));
        let config = WasmChip::<F>::configure(cs, wb_table, shared_state);

        config
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let mut wasm_chip = WasmChip::construct(config);

        wasm_chip.load_once(&mut layouter).unwrap();
        layouter.assign_region(
            || "wasm_chip region",
            |mut region| {
                wasm_chip.config.shared_state.borrow_mut().reset();
                let mut assign_delta = self.assign_delta_base;
                for wb in &self.wbs {
                    wasm_chip.load(&mut region, wb, assign_delta).unwrap();
                    assign_delta = wasm_chip
                        .assign_auto(&mut region, wb, self.wb_offset, assign_delta)
                        .unwrap();
                    debug!(
                        "RESULT error_code {}",
                        wasm_chip.config.shared_state.borrow().error_code
                    );
                }

                Ok(())
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

    fn test<'a, F: Field>(test_circuit: &TestCircuit<F>, is_ok: bool, k: u32) {
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
        k: u32,
    ) {
        let prover = MockProver::run(k, test_circuit, vec![]).unwrap();
        if is_ok {
            prover.assert_satisfied();
        } else {
            assert!(prover.verify().is_err());
        }
    }

    #[test]
    pub fn file1_ok() {
        let path = "./test_files/cc1.wat";
        let data: Vec<u8> = std::fs::read(path).unwrap();
        let bytes = wat2wasm(data).unwrap();
        let wb = WasmBytecode::new(bytes);
        debug_wb(&wb);
        let circuit = TestCircuit::<Fr> {
            wbs: vec![wb],
            ..Default::default()
        };
        test(&circuit, true, 9);
    }

    #[test]
    pub fn file1_with_random_assign_delta_base_ok() {
        let path = "./test_files/cc1.wat";
        let data: Vec<u8> = std::fs::read(path).unwrap();
        let bytes = wat2wasm(data).unwrap();
        let wb = WasmBytecode::new(bytes);
        debug_wb(&wb);
        let circuit = TestCircuit::<Fr> {
            wbs: vec![wb],
            assign_delta_base: thread_rng().gen_range(5..5000),
            ..Default::default()
        };
        test(&circuit, true, 13);
    }

    #[test]
    pub fn file2_ok() {
        let path = "./test_files/cc2.wat";
        let data: Vec<u8> = std::fs::read(path).unwrap();
        let bytes = wat2wasm(data).unwrap();
        let wb = WasmBytecode::new(bytes);
        debug_wb(&wb);
        let circuit = TestCircuit::<Fr> {
            wbs: vec![wb],
            ..Default::default()
        };
        test(&circuit, true, 9);
    }

    #[test]
    pub fn file3_ok() {
        let path = "./test_files/cc3.wat";
        let data: Vec<u8> = std::fs::read(path).unwrap();
        let bytes = wat2wasm(data).unwrap();
        let wb = WasmBytecode::new(bytes);
        debug_wb(&wb);
        let circuit = TestCircuit::<Fr> {
            wbs: vec![wb],
            ..Default::default()
        };
        test(&circuit, true, 9);
    }

    // #[ignore]
    #[test]
    pub fn multiple_bytecodes_assignment_ok() {
        let paths = [
            "./test_files/cc1.wat",
            "./test_files/cc2.wat",
            "./test_files/cc3.wat",
        ];
        let mut wbs = vec![];
        for path in paths {
            debug!("processing file '{}'", path);
            let data: Vec<u8> = std::fs::read(path).unwrap();
            let bytes = wat2wasm(data).unwrap();
            let wb = WasmBytecode::new(bytes);
            wbs.push(wb);
        }
        let circuit = TestCircuit::<Fr> {
            wbs,
            ..Default::default()
        };
        test(&circuit, true, 13);
    }

    #[test]
    pub fn invalid_bytecode_parse_error_ok() {
        let paths = [
            "./test_files/cc1.wat",
            "./test_files/cc2.wat",
            "./test_files/cc3.wat",
        ];
        for path in paths {
            let data: Vec<u8> = std::fs::read(path).unwrap();
            let bytes = wat2wasm(data).unwrap();
            let mut wb = WasmBytecode::new(bytes);
            let i: usize = random::<usize>() % WASM_MAGIC_PREFIX_LEN;
            mutate_byte(&mut wb.bytes[i]);
            let circuit = TestCircuitWithErrorProcessing::<Fr> {
                wbs: vec![wb],
                ..Default::default()
            };
            test_with_error_processing(&circuit, true, 9);
        }
    }

    #[test]
    pub fn bad_magic_prefix_parse_error_ok() {
        let paths = [
            "./test_files/cc1.wat",
            "./test_files/cc2.wat",
            "./test_files/cc3.wat",
        ];
        for path in paths {
            let data: Vec<u8> = std::fs::read(path).unwrap();
            let bytes = wat2wasm(data).unwrap();
            let mut wb = WasmBytecode::new(bytes);
            let i: usize = random::<usize>() % WASM_MAGIC_PREFIX_LEN;
            mutate_byte(&mut wb.bytes[i]);
            let circuit = TestCircuitWithErrorProcessing::<Fr> {
                wbs: vec![wb],
                ..Default::default()
            };
            test_with_error_processing(&circuit, true, 12);
        }
    }

    #[test]
    pub fn bad_version_parse_error_ok() {
        let paths = [
            "./test_files/cc1.wat",
            "./test_files/cc2.wat",
            "./test_files/cc3.wat",
        ];
        for path in paths {
            debug!("processing file '{}'", path);
            let data: Vec<u8> = std::fs::read(path).unwrap();
            let bytes = wat2wasm(data).unwrap();
            let mut wb = WasmBytecode::new(bytes);
            let i: usize =
                WASM_VERSION_PREFIX_START_INDEX + random::<usize>() % WASM_VERSION_PREFIX_LEN;
            mutate_byte(&mut wb.bytes[i]);
            let circuit = TestCircuitWithErrorProcessing::<Fr> {
                wbs: vec![wb],
                ..Default::default()
            };
            test_with_error_processing(&circuit, true, 12);
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
        test_with_error_processing(&circuit, false, 9);
    }

    #[test]
    pub fn file1_invalid_magic_prefix_parse_error_ok() {
        let path = "./test_files/cc1.wat";
        let data: Vec<u8> = std::fs::read(path).unwrap();
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
        test_with_error_processing(&circuit, true, 9);
    }

    #[test]
    pub fn file1_invalid_version_parse_error_ok() {
        let path = "./test_files/cc1.wat";
        let data: Vec<u8> = std::fs::read(path).unwrap();
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
        test_with_error_processing(&circuit, true, 9);
    }

    #[test]
    pub fn file1_invalid_section_id_parse_error_ok() {
        let path = "./test_files/cc1.wat";
        let data: Vec<u8> = std::fs::read(path).unwrap();
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
        test_with_error_processing(&circuit, true, 9);
    }
}
