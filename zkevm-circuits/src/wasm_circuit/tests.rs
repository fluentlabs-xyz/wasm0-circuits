use std::cell::RefCell;
use std::marker::PhantomData;
use std::rc::Rc;

use halo2_proofs::{
    plonk::{ConstraintSystem, Error},
};
use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner};
use halo2_proofs::plonk::Circuit;
use log::debug;

use eth_types::{Field, Hash, ToWord};

use crate::wasm_circuit::bytecode::bytecode::WasmBytecode;
use crate::wasm_circuit::bytecode::bytecode_table::WasmBytecodeTable;
use crate::wasm_circuit::circuit::{WasmChip, WasmConfig};
use crate::wasm_circuit::types::SharedState;

#[derive(Default)]
struct TestCircuit<F> {
    bytes: Vec<u8>,
    code_hash: Hash,
    error_code: u64,
    _marker: PhantomData<F>,
}

impl<F: Field> Circuit<F> for TestCircuit<F> {
    type Config = WasmConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self { Self::default() }

    fn configure(cs: &mut ConstraintSystem<F>) -> Self::Config {
        let mut shared_state = Rc::new(RefCell::new(SharedState::default()));
        shared_state.borrow_mut().error_processing_enabled = true;
        let wb_table = WasmBytecodeTable::construct(cs);
        let config = WasmChip::<F>::configure(cs, Rc::new(wb_table), shared_state);

        config
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let mut wasm_chip = WasmChip::construct(config);
        let wb = WasmBytecode::new(self.bytes.clone(), self.code_hash.to_word());

        wasm_chip.load(&mut layouter, &wb).unwrap();

        layouter.assign_region(
            || "wasm_chip region",
            |mut region| {
                wasm_chip.config.shared_state.borrow_mut().reset();
                wasm_chip.assign_auto(
                    &mut region,
                    &wb,
                    0,
                    0,
                ).unwrap();
                debug!("RESULT error_code {}", wasm_chip.config.shared_state.borrow().error_code);

                Ok(())
            }
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod wasm_circuit_tests {
    use std::marker::PhantomData;

    use ethers_core::k256::pkcs8::der::Encode;
    use halo2_proofs::dev::MockProver;
    use halo2_proofs::halo2curves::bn256::Fr;
    use log::debug;
    use rand::{random, Rng, thread_rng};
    use wabt::wat2wasm;

    use bus_mapping::state_db::CodeDB;
    use eth_types::Field;

    use crate::wasm_circuit::consts::{WASM_MAGIC_PREFIX, WASM_MAGIC_PREFIX_END_INDEX, WASM_MAGIC_PREFIX_START_INDEX, WASM_VERSION_PREFIX_END_INDEX, WASM_VERSION_PREFIX_LEN, WASM_VERSION_PREFIX_START_INDEX};
    use crate::wasm_circuit::tests::TestCircuit;
    use crate::wasm_circuit::tests_helpers::mutate_byte;
    use crate::wasm_circuit::types::WasmSection;

    fn test<'a, F: Field>(test_circuit: TestCircuit<F>, is_ok: bool) {
        let k = 10;
        let prover = MockProver::run(k, &test_circuit, vec![]).unwrap();
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
        let wb = wat2wasm(data).unwrap();
        debug!("wb.len: {}", wb.len());
        debug!("wb.len hex: {:x?}", wb.len());
        debug!("wb last_index: {}", wb.len() - 1);
        debug!("wb last_index hex: {:x?}", wb.len() - 1);
        debug!("wb: {:x?}", wb);
        let code_hash = CodeDB::hash(&wb);
        let circuit = TestCircuit::<Fr> {
            _marker: PhantomData,

            bytes: wb.clone(),
            code_hash,
            ..Default::default()
        };
        self::test(circuit, true);
    }

    #[test]
    pub fn file2_ok() {
        let path_to_file = "./test_files/cc2.wat";
        let data: Vec<u8> = std::fs::read(path_to_file).unwrap();
        let wb = wat2wasm(data).unwrap();
        debug!("wb.len: {}", wb.len());
        debug!("wb.len hex: {:x?}", wb.len());
        debug!("wb last_index: {}", wb.len() - 1);
        debug!("wb last_index hex: {:x?}", wb.len() - 1);
        debug!("wb: {:x?}", wb);
        let mut code_hash = CodeDB::hash(&wb);
        let circuit = TestCircuit::<Fr> {
            _marker: PhantomData,

            bytes: wb.clone(),
            code_hash,
            ..Default::default()
        };
        self::test(circuit, true);
    }

    #[test]
    pub fn file3_ok() {
        let path_to_file = "./test_files/cc3.wat";
        let data: Vec<u8> = std::fs::read(path_to_file).unwrap();
        let wb = wat2wasm(data).unwrap();
        debug!("wb.len: {}", wb.len());
        debug!("wb.len hex: {:x?}", wb.len());
        debug!("wb last index: {}", wb.len() - 1);
        debug!("wb last index hex: {:x?}", wb.len() - 1);
        debug!("wb: {:x?}", wb);
        let mut code_hash = CodeDB::hash(&wb);
        let circuit = TestCircuit::<Fr> {
            _marker: PhantomData,

            bytes: wb.clone(),
            code_hash,
            ..Default::default()
        };
        self::test(circuit, true);
    }

    #[test]
    pub fn invalid_bytecode_fails() {
        let paths_to_files = [
            "./test_files/cc1.wat",
            "./test_files/cc2.wat",
            "./test_files/cc3.wat",
        ];
        for path_to_file in paths_to_files {
            let data: Vec<u8> = std::fs::read(path_to_file).unwrap();
            let mut wb = wat2wasm(data).unwrap();
            let i: usize = random::<usize>() % (WASM_MAGIC_PREFIX.len() - 1) + 1; // exclude \0 char at 0 index
            mutate_byte(&mut wb[i]);
            let circuit = TestCircuit::<Fr> {
                _marker: PhantomData,

                bytes: wb.clone(),
                code_hash: CodeDB::hash(&wb),
                ..Default::default()
            };
            self::test(circuit, true);
        }
    }

    #[test]
    pub fn bad_magic_prefix_fails() {
        let paths_to_files = [
            "./test_files/cc1.wat",
            "./test_files/cc2.wat",
            "./test_files/cc3.wat",
        ];
        for path_to_file in paths_to_files {
            let data: Vec<u8> = std::fs::read(path_to_file).unwrap();
            let mut wb = wat2wasm(data).unwrap();
            let i: usize = random::<usize>() % (WASM_MAGIC_PREFIX.len() - 1) + 1; // exclude \0 char at 0 index
            mutate_byte(&mut wb[i]);
            let circuit = TestCircuit::<Fr> {
                _marker: PhantomData,

                bytes: wb.clone(),
                code_hash: CodeDB::hash(&wb),
                ..Default::default()
            };
            self::test(circuit, true);
        }
    }

    #[test]
    pub fn bad_version_fails() {
        let paths_to_files = [
            "./test_files/cc1.wat",
            "./test_files/cc2.wat",
            "./test_files/cc3.wat",
        ];
        for path_to_file in paths_to_files {
            let data: Vec<u8> = std::fs::read(path_to_file).unwrap();
            let mut wb = wat2wasm(data).unwrap();
            let i: usize = WASM_VERSION_PREFIX_START_INDEX + random::<usize>() % WASM_VERSION_PREFIX_LEN;
            mutate_byte(&mut wb[i]);
            let circuit = TestCircuit::<Fr> {
                _marker: PhantomData,

                bytes: wb.clone(),
                code_hash: CodeDB::hash(&wb),
                ..Default::default()
            };
            self::test(circuit, true);
        }
    }

    #[ignore] // TODO some problems after new module integration
    #[test]
    pub fn test_random_bytecode_must_fail() {
        let wb: Vec<u8> = [0, 1, 2, 3].to_vec().unwrap();
        let circuit = TestCircuit::<Fr> {
            _marker: PhantomData,

            bytes: wb.clone(),
            code_hash: CodeDB::hash(&wb),
            ..Default::default()
        };
        self::test(circuit, false);
    }

    #[test]
    pub fn parse_error_file1_invalid_magic_prefix_ok() {
        let path_to_file = "./test_files/cc1.wat";
        let data: Vec<u8> = std::fs::read(path_to_file).unwrap();
        let mut wb = wat2wasm(data).unwrap();
        debug!("wb.len: {}", wb.len());
        debug!("wb.len hex: {:x?}", wb.len());
        debug!("wb last_index: {}", wb.len() - 1);
        debug!("wb last_index hex: {:x?}", wb.len() - 1);
        debug!("wb (original): {:x?}", wb);

        // mutate some data
        let idx: usize = thread_rng().gen_range(WASM_MAGIC_PREFIX_START_INDEX..=WASM_MAGIC_PREFIX_END_INDEX);
        mutate_byte(&mut wb[idx]);

        debug!("wb (modified): {:x?}", wb);
        let circuit = TestCircuit::<Fr> {
            _marker: PhantomData,

            bytes: wb.clone(),
            code_hash: CodeDB::hash(&wb),
            ..Default::default()
        };
        self::test(circuit, true);
    }

    #[test]
    pub fn parse_error_file1_invalid_version_ok() {
        let path_to_file = "./test_files/cc1.wat";
        let data: Vec<u8> = std::fs::read(path_to_file).unwrap();
        let mut wb = wat2wasm(data).unwrap();
        debug!("wb.len: {}", wb.len());
        debug!("wb.len hex: {:x?}", wb.len());
        debug!("wb last_index: {}", wb.len() - 1);
        debug!("wb last_index hex: {:x?}", wb.len() - 1);
        debug!("wb (original): {:x?}", wb);

        // mutate some data
        let idx: usize = thread_rng().gen_range(WASM_VERSION_PREFIX_START_INDEX..=WASM_VERSION_PREFIX_END_INDEX);
        mutate_byte(&mut wb[idx]);

        debug!("wb (modified): {:x?}", wb);
        let circuit = TestCircuit::<Fr> {
            _marker: PhantomData,

            bytes: wb.clone(),
            code_hash: CodeDB::hash(&wb),
            ..Default::default()
        };
        self::test(circuit, true);
    }

    #[test]
    pub fn parse_error_file1_invalid_section_id_ok() {
        let path_to_file = "./test_files/cc1.wat";
        let data: Vec<u8> = std::fs::read(path_to_file).unwrap();
        let mut wb = wat2wasm(data).unwrap();
        debug!("wb.len: {}", wb.len());
        debug!("wb.len hex: {:x?}", wb.len());
        debug!("wb last_index: {}", wb.len() - 1);
        debug!("wb last_index hex: {:x?}", wb.len() - 1);
        debug!("wb (original): {:x?}", wb);

        // change section ID to some unknown
        wb[8] = thread_rng().gen_range((WasmSection::DataCount as u8 + 1)..255);

        debug!("wb (modified): {:x?}", wb);
        let circuit = TestCircuit::<Fr> {
            _marker: PhantomData,

            bytes: wb.clone(),
            code_hash: CodeDB::hash(&wb),
            ..Default::default()
        };
        self::test(circuit, true);
    }
}