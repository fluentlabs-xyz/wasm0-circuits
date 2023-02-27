//! The EVM circuit implementation.

#![allow(missing_docs)]

use halo2_proofs::{
    circuit::{Layouter, Value},
    plonk::*,
};
use strum::IntoEnumIterator;
use eth_types::{Field, ToWord};

use crate::util::{Challenges, SubCircuit, SubCircuitConfig};
pub use crate::witness;
use crate::evm_circuit::table::FixedTableTag;
use crate::wasm_circuit::circuits::brtable::{BrTableConfig};
use crate::wasm_circuit::circuits::CircuitConfigure;
use crate::wasm_circuit::circuits::config::{IMTABLE_COLUMNS, VAR_COLUMNS};
use crate::wasm_circuit::circuits::etable_compact::{EventTableConfig};
use crate::wasm_circuit::circuits::imtable::{InitMemoryTableConfig};
use crate::wasm_circuit::circuits::itable::{InstructionTableConfig};
use crate::wasm_circuit::circuits::jtable::{JumpTableConfig};
use crate::wasm_circuit::circuits::mtable_compact::{MemoryTableConfig};
use crate::wasm_circuit::circuits::rtable::{RangeTableConfig};
use crate::wasm_circuit::specs::{CompilationTable, ExecutionTable};
use crate::witness::{Block, Call, Transaction};

mod circuits;
mod specs;
mod test;
mod traits;

/// EvmCircuitConfig implements verification of execution trace of a block.
#[derive(Clone)]
pub struct WasmCircuitConfig<F: Field> {
    rtable: RangeTableConfig<F>,
    itable: InstructionTableConfig<F>,
    imtable: InitMemoryTableConfig<F>,
    mtable: MemoryTableConfig<F>,
    jtable: JumpTableConfig<F>,
    etable: EventTableConfig<F>,
    brtable: BrTableConfig<F>,
}

/// Circuit configuration arguments
pub struct WasmCircuitConfigArgs {
    compilation_tables: CompilationTable,
    execution_tables: ExecutionTable,
}

impl<F: Field> SubCircuitConfig<F> for WasmCircuitConfig<F> {
    type ConfigArgs = WasmCircuitConfigArgs;

    /// Configure WasmCircuitConfig
    #[allow(clippy::too_many_arguments)]
    fn new(
        meta: &mut ConstraintSystem<F>,
        Self::ConfigArgs {
            compilation_tables,
            execution_tables,
        }: Self::ConfigArgs,
    ) -> Self {

        let circuit_configure = CircuitConfigure {
            first_consecutive_zero_memory_offset: compilation_tables.imtable.first_consecutive_zero_memory(),
            initial_memory_pages: compilation_tables.configure_table.init_memory_pages as u64,
            maximal_memory_pages: compilation_tables.configure_table.maximal_memory_pages as u64,
            opcode_selector: compilation_tables.itable.opcode_class(),
        };

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

        Self {
            rtable,
            itable,
            imtable,
            mtable,
            jtable,
            etable,
            brtable,
        }
    }
}

/// Tx Circuit for verifying transaction signatures
#[derive(Clone, Default, Debug)]
pub struct WasmCircuit<F: Field> {
    /// Block
    pub block: Option<Block<F>>,
    fixed_table_tags: Vec<FixedTableTag>,
}

impl<F: Field> WasmCircuit<F> {
    /// Return a new WasmCircuit
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
}

impl<F: Field> SubCircuit<F> for WasmCircuit<F> {
    type Config = WasmCircuitConfig<F>;

    fn new_from_block(block: &witness::Block<F>) -> Self {
        Self::new(block.clone())
    }

    /// Return the minimum number of rows required to prove the block
    fn min_num_rows_block(block: &witness::Block<F>) -> (usize, usize) {
        (0, 0)
    }

    /// Make the assignments to the WasmCircuit
    fn synthesize_sub(
        &self,
        config: &Self::Config,
        challenges: &Challenges<Value<F>>,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        let block = self.block.as_ref().unwrap();

        let mut offset = 0;

        let dummy_tx = Transaction::default();
        let last_call = block
            .txs
            .last()
            .map(|tx| tx.calls[0].clone())
            .unwrap_or_else(Call::default);
        let end_block_not_last = &block.end_block_not_last;
        let end_block_last = &block.end_block_last;
        // Collect all steps
        let mut steps = block
            .txs
            .iter()
            .flat_map(|tx| {
                tx.steps
                    .iter()
                    .map(move |step| (tx, &tx.calls[step.call_index], step))
            })
            .chain(std::iter::once((&dummy_tx, &last_call, end_block_not_last)))
            .peekable();

        // part1: assign real steps
        loop {
            let (transaction, call, step) = steps.next().expect("should not be empty");
            let next = steps.peek();
            if next.is_none() {
                break;
            }
            let height = step.execution_state.get_step_height();

            let compilation_tables = CompilationTable {
                itable: Default::default(),
                imtable: Default::default(),
                elem_table: Default::default(),
                configure_table: Default::default(),
            };
            let execution_tables = ExecutionTable {
                etable: Default::default(),
                mtable: Default::default(),
                jtable: Default::default(),
            };
            if let Some(bytecode) = block.bytecodes.get(&transaction.callee_address.to_word()) {
                let tables = wasm_tracer::extract_wasm_trace(&bytecode.bytes).expect("can't create wasm trace");
            }

            // let rchip = RangeTableChip::new(config.rtable.clone());
            // let ichip = InstructionTableChip::new(config.itable.clone());
            // let imchip = MInitTableChip::new(config.imtable.clone());
            // let mchip = MemoryTableChip::new(config.mtable.clone());
            // let jchip = JumpTableChip::new(config.jtable.clone());
            // let echip = EventTableChip::new(config.etable.clone());
            // let brchip = BrTableChip::new(config.brtable.clone());
            //
            // rchip.init(layouter)?;
            // ichip.assign(layouter, &self.compilation_tables.itable)?;
            // brchip.assign(
            //     layouter,
            //     &self.tables.compilation_tables.itable.create_brtable(),
            //     &self.tables.compilation_tables.elem_table,
            // )?;
            // if self.tables.compilation_tables.imtable.entries().len() > 0 {
            //     imchip.assign(layouter, &self.tables.compilation_tables.imtable)?;
            // }
            //
            // layouter.assign_region(
            //     || "jtable mtable etable",
            //     |region| {
            //         let mut ctx = Context::new(region);
            //
            //         let (rest_mops_cell, rest_jops_cell) = {
            //             echip.assign(
            //                 &mut ctx,
            //                 &self.tables.execution_tables.etable,
            //                 self.tables.compilation_tables.configure_table,
            //             )?
            //         };
            //
            //         ctx.reset();
            //         mchip.assign(
            //             &mut ctx,
            //             &self.tables.execution_tables.mtable,
            //             rest_mops_cell,
            //             self.tables
            //                 .compilation_tables
            //                 .imtable
            //                 .first_consecutive_zero_memory(),
            //         )?;
            //
            //         ctx.reset();
            //         jchip.assign(
            //             &mut ctx,
            //             &self.tables.execution_tables.jtable,
            //             rest_jops_cell,
            //         )?;
            //
            //         Ok(())
            //     },
            // )?;


            offset += height;
        }

        Ok(())
    }
}