//! The EVM circuit implementation.

#![allow(missing_docs)]

use std::marker::PhantomData;
use halo2_proofs::{
    circuit::{Layouter, Value},
    plonk::*,
};

mod execution;
pub mod param;
pub(crate) mod step;
pub(crate) mod util;

pub mod table;

use crate::table::{BlockTable, BytecodeTable, CopyTable, ExpTable, KeccakTable, RwTable, TxTable};
use crate::util::{Challenges, SubCircuit, SubCircuitConfig};
pub use crate::witness;
use bus_mapping::evm::OpcodeId;
use eth_types::Field;
use execution::ExecutionConfig;
use itertools::Itertools;
use strum::IntoEnumIterator;
use table::FixedTableTag;
use witness::Block;

/// EvmCircuitConfig implements verification of execution trace of a block.
#[derive(Clone, Debug)]
pub struct EvmCircuitConfig<F> {
    fixed_table: [Column<Fixed>; 4],
    byte_table: [Column<Fixed>; 1],
    // pub(crate) execution: Box<ExecutionConfig<F>>,
    // External tables
    tx_table: TxTable,
    rw_table: RwTable,
    bytecode_table: BytecodeTable,
    block_table: BlockTable,
    copy_table: CopyTable,
    keccak_table: KeccakTable,
    exp_table: ExpTable,
    phantom: PhantomData<F>,
}

/// Circuit configuration arguments
pub struct EvmCircuitConfigArgs<F: Field> {
    /// Challenge
    pub challenges: Challenges<Expression<F>>,
    /// TxTable
    pub tx_table: TxTable,
    /// RwTable
    pub rw_table: RwTable,
    /// BytecodeTable
    pub bytecode_table: BytecodeTable,
    /// BlockTable
    pub block_table: BlockTable,
    /// CopyTable
    pub copy_table: CopyTable,
    /// KeccakTable
    pub keccak_table: KeccakTable,
    /// ExpTable
    pub exp_table: ExpTable,
}

impl<F: Field> SubCircuitConfig<F> for EvmCircuitConfig<F> {
    type ConfigArgs = EvmCircuitConfigArgs<F>;

    /// Configure EvmCircuitConfig
    #[allow(clippy::too_many_arguments)]
    fn new(
        meta: &mut ConstraintSystem<F>,
        Self::ConfigArgs {
            challenges,
            tx_table,
            rw_table,
            bytecode_table,
            block_table,
            copy_table,
            keccak_table,
            exp_table,
        }: Self::ConfigArgs,
    ) -> Self {
        let fixed_table = [(); 4].map(|_| meta.fixed_column());
        let byte_table = [(); 1].map(|_| meta.fixed_column());
        // let execution = Box::new(ExecutionConfig::configure(
        //     meta,
        //     challenges,
        //     &fixed_table,
        //     &byte_table,
        //     &tx_table,
        //     &rw_table,
        //     &bytecode_table,
        //     &block_table,
        //     &copy_table,
        //     &keccak_table,
        //     &exp_table,
        // ));

        Self {
            fixed_table,
            byte_table,
            // execution,
            tx_table,
            rw_table,
            bytecode_table,
            block_table,
            copy_table,
            keccak_table,
            exp_table,
            phantom: Default::default(),
        }
    }
}

impl<F: Field> EvmCircuitConfig<F> {
    /// Load fixed table
    pub fn load_fixed_table(
        &self,
        layouter: &mut impl Layouter<F>,
        fixed_table_tags: Vec<FixedTableTag>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "fixed table",
            |mut region| {
                for (offset, row) in std::iter::once([F::zero(); 4])
                    .chain(fixed_table_tags.iter().flat_map(|tag| tag.build()))
                    .enumerate()
                {
                    for (column, value) in self.fixed_table.iter().zip_eq(row) {
                        region.assign_fixed(|| "", *column, offset, || Value::known(value))?;
                    }
                }

                Ok(())
            },
        )
    }

    /// Load byte table
    pub fn load_byte_table(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        layouter.assign_region(
            || "byte table",
            |mut region| {
                for offset in 0..256 {
                    region.assign_fixed(
                        || "",
                        self.byte_table[0],
                        offset,
                        || Value::known(F::from(offset as u64)),
                    )?;
                }

                Ok(())
            },
        )
    }
}

/// Tx Circuit for verifying transaction signatures
#[derive(Clone, Default, Debug)]
pub struct EvmCircuit<F: Field> {
    /// Block
    pub block: Option<Block<F>>,
    fixed_table_tags: Vec<FixedTableTag>,
}

impl<F: Field> EvmCircuit<F> {
    /// Return a new EvmCircuit
    pub fn new(block: Block<F>) -> Self {
        Self {
            block: Some(block),
            fixed_table_tags: FixedTableTag::iter().collect(),
        }
    }

    pub fn new_dev(block: Block<F>, fixed_table_tags: Vec<FixedTableTag>) -> Self {
        Self {
            block: Some(block),
            fixed_table_tags,
        }
    }

    /// Calculate which rows are "actually" used in the circuit
    pub fn get_active_rows(block: &Block<F>) -> (Vec<usize>, Vec<usize>) {
        let max_offset = Self::get_num_rows_required(block);
        // some gates are enabled on all rows
        let gates_row_ids = (0..max_offset).collect();
        // lookups are enabled at "q_step" rows and byte lookup rows
        let lookup_row_ids = (0..max_offset).collect();
        (gates_row_ids, lookup_row_ids)
    }

    pub fn get_num_rows_required(block: &Block<F>) -> usize {
        // Start at 1 so we can be sure there is an unused `next` row available
        let mut num_rows = 1;
        let evm_rows = block.evm_circuit_pad_to;
        if evm_rows == 0 {
            for transaction in &block.txs {
                for step in &transaction.steps {
                    num_rows += step.execution_state.get_step_height();
                }
            }
            num_rows += 1; // EndBlock
        } else {
            num_rows += block.evm_circuit_pad_to;
        }
        num_rows
    }
}

impl<F: Field> SubCircuit<F> for EvmCircuit<F> {
    type Config = EvmCircuitConfig<F>;

    fn new_from_block(block: &witness::Block<F>) -> Self {
        Self::new(block.clone())
    }

    /// Return the minimum number of rows required to prove the block
    fn min_num_rows_block(block: &witness::Block<F>) -> (usize, usize) {
        let num_rows_required_for_execution_steps: usize = Self::get_num_rows_required(block);
        let num_rows_required_for_fixed_table: usize = detect_fixed_table_tags(block)
            .iter()
            .map(|tag| tag.build::<F>().count())
            .sum();
        (
            std::cmp::max(
                num_rows_required_for_execution_steps,
                num_rows_required_for_fixed_table,
            ),
            block.evm_circuit_pad_to,
        )
    }

    /// Make the assignments to the EvmCircuit
    fn synthesize_sub(
        &self,
        config: &Self::Config,
        challenges: &Challenges<Value<F>>,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        let block = self.block.as_ref().unwrap();

        config.load_fixed_table(layouter, self.fixed_table_tags.clone())?;
        config.load_byte_table(layouter)?;
        // config.execution.assign_block(layouter, block, challenges)
        Ok(())
    }
}

/// create fixed_table_tags needed given witness block
pub(crate) fn detect_fixed_table_tags<F: Field>(block: &Block<F>) -> Vec<FixedTableTag> {
    let need_bitwise_lookup = block.txs.iter().any(|tx| {
        tx.steps.iter().any(|step| {
            matches!(
                step.opcode,
                Some(OpcodeId::AND)
                    | Some(OpcodeId::OR)
                    | Some(OpcodeId::XOR)
                    | Some(OpcodeId::NOT)
            )
        })
    });
    FixedTableTag::iter()
        .filter(|t| {
            !matches!(
                t,
                FixedTableTag::BitwiseAnd | FixedTableTag::BitwiseOr | FixedTableTag::BitwiseXor
            ) || need_bitwise_lookup
        })
        .collect()
}

#[cfg(any(feature = "test", test))]
pub mod test {
    use super::*;
    use crate::{
        evm_circuit::{witness::Block, EvmCircuitConfig},
        table::{BlockTable, BytecodeTable, CopyTable, ExpTable, KeccakTable, RwTable, TxTable},
        util::Challenges,
    };

    use eth_types::{Field, Word};

    use halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner},
        plonk::{Circuit, ConstraintSystem, Error},
    };
    use rand::{
        distributions::uniform::{SampleRange, SampleUniform},
        random, thread_rng, Rng,
    };

    pub(crate) fn rand_range<T, R>(range: R) -> T
    where
        T: SampleUniform,
        R: SampleRange<T>,
    {
        thread_rng().gen_range(range)
    }

    pub(crate) fn rand_bytes(n: usize) -> Vec<u8> {
        (0..n).map(|_| random()).collect()
    }

    pub(crate) fn rand_bytes_array<const N: usize>() -> [u8; N] {
        [(); N].map(|_| random())
    }

    pub(crate) fn rand_word() -> Word {
        Word::from_big_endian(&rand_bytes_array::<32>())
    }

    impl<F: Field> Circuit<F> for EvmCircuit<F> {
        type Config = (EvmCircuitConfig<F>, Challenges);
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            let tx_table = TxTable::construct(meta);
            let rw_table = RwTable::construct(meta);
            let bytecode_table = BytecodeTable::construct(meta);
            let block_table = BlockTable::construct(meta);
            let q_copy_table = meta.fixed_column();
            let copy_table = CopyTable::construct(meta, q_copy_table);
            let keccak_table = KeccakTable::construct(meta);
            let exp_table = ExpTable::construct(meta);
            let challenges = Challenges::construct(meta);
            let challenges_expr = challenges.exprs(meta);

            (
                EvmCircuitConfig::new(
                    meta,
                    EvmCircuitConfigArgs {
                        challenges: challenges_expr,
                        tx_table,
                        rw_table,
                        bytecode_table,
                        block_table,
                        copy_table,
                        keccak_table,
                        exp_table,
                    },
                ),
                challenges,
            )
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            let block = self.block.as_ref().unwrap();

            let (config, challenges) = config;
            let challenges = challenges.values(&mut layouter);

            config.tx_table.load(
                &mut layouter,
                &block.txs,
                block.circuits_params.max_txs,
                &challenges,
            )?;
            block.rws.check_rw_counter_sanity();
            config.rw_table.load(
                &mut layouter,
                &block.rws.table_assignments(),
                block.circuits_params.max_rws,
                challenges.evm_word(),
            )?;
            config
                .bytecode_table
                .load(&mut layouter, block.bytecodes.values(), &challenges)?;
            config
                .block_table
                .load(&mut layouter, &block.context, challenges.evm_word())?;
            config.copy_table.load(&mut layouter, block, &challenges)?;
            config
                .keccak_table
                .dev_load(&mut layouter, &block.sha3_inputs, &challenges)?;
            config.exp_table.load(&mut layouter, block)?;

            self.synthesize_sub(&config, &challenges, &mut layouter)
        }
    }

    impl<F: Field> EvmCircuit<F> {
        pub fn get_test_cicuit_from_block(block: Block<F>) -> Self {
            let fixed_table_tags = detect_fixed_table_tags(&block);
            EvmCircuit::<F>::new_dev(block, fixed_table_tags)
        }
    }
}

#[cfg(test)]
mod evm_circuit_stats {
    use crate::evm_circuit::step::ExecutionState;
    use crate::test_util::CircuitTestBuilder;

    use eth_types::{bytecode, evm_types::OpcodeId, geth_types::GethData};

    use mock::test_ctx::{helpers::*, TestContext};
    use strum::IntoEnumIterator;

    #[test]
    pub fn empty_evm_circuit_no_padding() {
        CircuitTestBuilder::new_from_test_ctx(
            TestContext::<0, 0>::new(None, |_| {}, |_, _| {}, |b, _| b).unwrap(),
        )
        .run();
    }

    #[test]
    pub fn empty_evm_circuit_with_padding() {
        CircuitTestBuilder::new_from_test_ctx(
            TestContext::<0, 0>::new(None, |_| {}, |_, _| {}, |b, _| b).unwrap(),
        )
        .block_modifier(Box::new(|block| block.evm_circuit_pad_to = (1 << 18) - 100))
        .run();
    }

    /// This function prints to stdout a table with all the implemented states
    /// and their responsible opcodes with the following stats:
    /// - height: number of rows in the EVM circuit used by the execution state
    /// - gas: gas value used for the opcode execution
    /// - height/gas: ratio between circuit cost and gas cost
    ///
    /// Run with:
    /// `cargo test -p zkevm-circuits --release get_evm_states_stats --
    /// --nocapture --ignored`
    #[ignore]
    #[test]
    pub fn get_evm_states_stats() {
        let mut implemented_states = Vec::new();
        for state in ExecutionState::iter() {
            let height = state.get_step_height_option();
            if let Some(h) = height {
                implemented_states.push((state, h));
            }
        }

        let mut stats = Vec::new();
        for (state, h) in implemented_states {
            for opcode in state.responsible_opcodes() {
                let mut code = bytecode! {
                    PUSH2(0x8000)
                    PUSH2(0x00)
                    PUSH2(0x10)
                    PUSH2(0x20)
                    PUSH2(0x30)
                    PUSH2(0x40)
                    PUSH2(0x50)
                };
                code.write_op(opcode);
                code.write_op(OpcodeId::STOP);
                let block: GethData = TestContext::<2, 1>::new(
                    None,
                    account_0_code_account_1_no_code(code),
                    tx_from_1_to_0,
                    |block, _tx| block.number(0xcafeu64),
                )
                .unwrap()
                .into();
                let gas_cost = block.geth_traces[0].struct_logs[7].gas_cost.0;
                stats.push((state, opcode, h, gas_cost));
            }
        }

        println!(
            "| {: <14} | {: <14} | {: <2} | {: >6} | {: <5} |",
            "state", "opcode", "h", "g", "h/g"
        );
        println!("| ---            | ---            | ---|    --- | ---   |");
        for (state, opcode, height, gas_cost) in stats {
            println!(
                "| {: <14?} | {: <14?} | {: >2} | {: >6} | {: >1.3} |",
                state,
                opcode,
                height,
                gas_cost,
                height as f64 / gas_cost as f64
            );
        }
    }
}
