use self::{
    brtable::{BrTableChip, BrTableConfig},
    config::{IMTABLE_COLUMNS, VAR_COLUMNS},
    etable_compact::{EventTableChip, EventTableConfig},
    jtable::{JumpTableChip, JumpTableConfig},
    mtable_compact::{MemoryTableChip, MemoryTableConfig},
};
use crate::wasm_circuit::{
    circuits::{
        imtable::{InitMemoryTableConfig, MInitTableChip},
        itable::{InstructionTableChip, InstructionTableConfig},
        rtable::{RangeTableChip, RangeTableConfig},
        utils::Context,
    },
};
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner},
    plonk::{
        create_proof, keygen_pk, keygen_vk, verify_proof, Circuit, ConstraintSystem, Error,
        Expression, ProvingKey, VerifyingKey, VirtualCells,
    },
    poly::commitment::{Params, ParamsVerifier},
    transcript::{Blake2bRead, Blake2bWrite, Challenge255},
};
use num_bigint::BigUint;
use crate::wasm_circuit::specs::{itable::OpcodeClassPlain, ExecutionTable, Tables};
use std::{
    collections::{BTreeSet},
    marker::PhantomData,
};
use eth_types::Field;

pub mod brtable;
pub mod config;
pub mod etable_compact;
pub mod imtable;
pub mod itable;
pub mod jtable;
pub mod mtable_compact;
pub mod rtable;
mod traits;
pub mod utils;

pub(crate) trait FromBn {
    fn zero() -> Self;
    fn from_bn(bn: &BigUint) -> Self;
}

#[derive(Clone)]
pub struct CircuitConfigure {
    pub initial_memory_pages: u64,
    pub maximal_memory_pages: u64,
    pub first_consecutive_zero_memory_offset: u64,
    pub opcode_selector: BTreeSet<OpcodeClassPlain>,
}

#[thread_local]
static mut CIRCUIT_CONFIGURE: Option<CircuitConfigure> = None;

#[derive(Clone)]
pub struct TestCircuitConfig<F: Field> {
    rtable: RangeTableConfig<F>,
    itable: InstructionTableConfig<F>,
    imtable: InitMemoryTableConfig<F>,
    mtable: MemoryTableConfig<F>,
    jtable: JumpTableConfig<F>,
    etable: EventTableConfig<F>,
    brtable: BrTableConfig<F>,
}

#[derive(Default, Clone)]
pub struct TestCircuit<F: Field> {
    pub tables: Tables,
    _data: PhantomData<F>,
}

impl<F: Field> TestCircuit<F> {
    pub fn new(tables: Tables) -> Self {
        unsafe {
            CIRCUIT_CONFIGURE = Some(CircuitConfigure {
                first_consecutive_zero_memory_offset: tables
                    .compilation_tables
                    .imtable
                    .first_consecutive_zero_memory(),
                initial_memory_pages: tables.compilation_tables.configure_table.init_memory_pages
                    as u64,
                maximal_memory_pages: tables
                    .compilation_tables
                    .configure_table
                    .maximal_memory_pages as u64,
                opcode_selector: tables.compilation_tables.itable.opcode_class(),
            });
        }

        TestCircuit {
            tables,
            _data: PhantomData,
        }
    }
}

impl<F: Field> Circuit<F> for TestCircuit<F> {
    type Config = TestCircuitConfig<F>;

    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        TestCircuit::new(Tables {
            compilation_tables: self.tables.compilation_tables.clone(),
            execution_tables: ExecutionTable::default(),
        })
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let circuit_configure = unsafe { CIRCUIT_CONFIGURE.clone().unwrap() };

        /*
         * Allocate a column to enable assign_advice_from_constant.
         */
        {
            let constants = meta.fixed_column();
            meta.enable_constant(constants);
            meta.enable_equality(constants);
        }

        let mut cols = [(); VAR_COLUMNS].map(|_| meta.advice_column()).into_iter();

        let rtable = RangeTableConfig::configure([(); 7].map(|_| meta.lookup_table_column()));
        let itable = InstructionTableConfig::configure(meta.lookup_table_column());
        let imtable = InitMemoryTableConfig::configure(
            [(); IMTABLE_COLUMNS].map(|_| meta.lookup_table_column()),
        );
        let mtable =
            MemoryTableConfig::configure(meta, &mut cols, &rtable, &imtable, &circuit_configure);
        let jtable = JumpTableConfig::configure(meta, &mut cols, &rtable);
        let brtable = BrTableConfig::configure(meta.lookup_table_column());

        let etable = EventTableConfig::configure(
            meta,
            &mut cols,
            &circuit_configure,
            &rtable,
            &itable,
            &mtable,
            &jtable,
            &brtable,
            &circuit_configure.opcode_selector,
        );

        Self::Config {
            rtable,
            itable,
            imtable,
            mtable,
            jtable,
            etable,
            brtable,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let rchip = RangeTableChip::new(config.rtable);
        let ichip = InstructionTableChip::new(config.itable);
        let imchip = MInitTableChip::new(config.imtable);
        let mchip = MemoryTableChip::new(config.mtable);
        let jchip = JumpTableChip::new(config.jtable);
        let echip = EventTableChip::new(config.etable);
        let brchip = BrTableChip::new(config.brtable);

        rchip.init(&mut layouter)?;
        ichip.assign(&mut layouter, &self.tables.compilation_tables.itable)?;
        brchip.assign(
            &mut layouter,
            &self.tables.compilation_tables.itable.create_brtable(),
            &self.tables.compilation_tables.elem_table,
        )?;
        if self.tables.compilation_tables.imtable.entries().len() > 0 {
            imchip.assign(&mut layouter, &self.tables.compilation_tables.imtable)?;
        }

        layouter.assign_region(
            || "jtable mtable etable",
            |region| {
                let mut ctx = Context::new(region);

                let (rest_mops_cell, rest_jops_cell) = {
                    echip.assign(
                        &mut ctx,
                        &self.tables.execution_tables.etable,
                        self.tables.compilation_tables.configure_table,
                    )?
                };

                ctx.reset();
                mchip.assign(
                    &mut ctx,
                    &self.tables.execution_tables.mtable,
                    rest_mops_cell,
                    self.tables
                        .compilation_tables
                        .imtable
                        .first_consecutive_zero_memory(),
                )?;

                ctx.reset();
                jchip.assign(
                    &mut ctx,
                    &self.tables.execution_tables.jtable,
                    rest_jops_cell,
                )?;

                Ok(())
            },
        )?;

        Ok(())
    }
}

trait Encode {
    fn encode(&self) -> BigUint;
}

pub(self) trait Lookup<F: Field> {
    fn encode(&self, meta: &mut VirtualCells<'_, F>) -> Expression<F>;

    fn configure_in_table(
        &self,
        meta: &mut ConstraintSystem<F>,
        key: &'static str,
        expr: impl FnOnce(&mut VirtualCells<'_, F>) -> Expression<F>,
    ) {
        meta.lookup_any(key, |meta| vec![(expr(meta), self.encode(meta))]);
    }
}

pub struct ZkWasmCircuitBuilder {
    pub tables: Tables,
}

const PARAMS: &str = "param.data";

impl ZkWasmCircuitBuilder {
    pub fn build_circuit<F: Field>(&self) -> TestCircuit<F> {
        TestCircuit::new(self.tables.clone())
    }

    // fn prepare_param(&self) -> Params<G1Affine> {
    //     let path = PathBuf::from(PARAMS);
    //
    //     if path.exists() {
    //         let mut fd = File::open(path.as_path()).unwrap();
    //         let mut buf = vec![];
    //
    //         fd.read_to_end(&mut buf).unwrap();
    //         Params::<G1Affine>::read(Cursor::new(buf)).unwrap()
    //     } else {
    //         // Initialize the polynomial commitment parameters
    //         let timer = start_timer!(|| format!("build params with K = {}", zkwasm_k()));
    //         let params: Params<G1Affine> = Params::<G1Affine>::unsafe_setup::<Bn256>(zkwasm_k());
    //         end_timer!(timer);
    //
    //         let mut fd = File::create(path.as_path()).unwrap();
    //         params.write(&mut fd).unwrap();
    //
    //         params
    //     }
    // }
    //
    // fn prepare_vk(
    //     &self,
    //     circuit: &TestCircuit<Fr>,
    //     params: &Params<G1Affine>,
    // ) -> VerifyingKey<G1Affine> {
    //     let timer = start_timer!(|| "build vk");
    //     let vk = keygen_vk(params, circuit).expect("keygen_vk should not fail");
    //     end_timer!(timer);
    //
    //     vk
    // }
    //
    // fn prepare_pk(
    //     &self,
    //     circuit: &TestCircuit<Fr>,
    //     params: &Params<G1Affine>,
    //     vk: VerifyingKey<G1Affine>,
    // ) -> ProvingKey<G1Affine> {
    //     let timer = start_timer!(|| "build pk");
    //     let pk = keygen_pk(&params, vk, circuit).expect("keygen_pk should not fail");
    //     end_timer!(timer);
    //     pk
    // }
    //
    // fn create_proof(
    //     &self,
    //     circuits: &[TestCircuit<Fr>],
    //     params: &Params<G1Affine>,
    //     pk: &ProvingKey<G1Affine>,
    //     public_inputs: &Vec<Fr>,
    // ) -> Vec<u8> {
    //     let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
    //
    //     let timer = start_timer!(|| "create proof");
    //     create_proof(
    //         params,
    //         pk,
    //         circuits,
    //         &[&[public_inputs]],
    //         OsRng,
    //         &mut transcript,
    //     )
    //     .expect("proof generation should not fail");
    //     end_timer!(timer);
    //
    //     transcript.finalize()
    // }
    //
    // fn verify_check(
    //     &self,
    //     vk: &VerifyingKey<G1Affine>,
    //     params: &Params<G1Affine>,
    //     proof: &Vec<u8>,
    //     public_inputs: &Vec<Fr>,
    // ) {
    //     let public_inputs_size = public_inputs.len();
    //
    //     let params_verifier: ParamsVerifier<Bn256> = params.verifier(public_inputs_size).unwrap();
    //
    //     let strategy = SingleVerifier::new(&params_verifier);
    //     let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
    //
    //     let timer = start_timer!(|| "verify proof");
    //     verify_proof(
    //         &params_verifier,
    //         vk,
    //         strategy,
    //         &[&[public_inputs]],
    //         &mut transcript,
    //     )
    //     .unwrap();
    //     end_timer!(timer);
    // }
    //
    // pub fn bench(&self, public_inputs: Vec<Fr>) {
    //     let circuit: TestCircuit<Fr> = self.build_circuit::<Fr>();
    //
    //     let params = self.prepare_param();
    //
    //     let vk = self.prepare_vk(&circuit, &params);
    //     let pk = self.prepare_pk(&circuit, &params, vk);
    //
    //     let proof = self.create_proof(&[circuit], &params, &pk, &public_inputs);
    //
    //     self.verify_check(pk.get_vk(), &params, &proof, &public_inputs);
    // }
}
