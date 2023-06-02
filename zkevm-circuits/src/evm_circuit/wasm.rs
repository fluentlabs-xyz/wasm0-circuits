use super::{
    param::{
        BLOCK_TABLE_LOOKUPS, BYTECODE_TABLE_LOOKUPS, COPY_TABLE_LOOKUPS, EXP_TABLE_LOOKUPS,
        FIXED_TABLE_LOOKUPS, KECCAK_TABLE_LOOKUPS, N_BYTE_LOOKUPS, N_COPY_COLUMNS,
        N_PHASE1_COLUMNS, RW_TABLE_LOOKUPS, TX_TABLE_LOOKUPS,
    },
    util::{instrumentation::Instrument, CachedRegion, CellManager, StoredExpression},
};
use crate::{
    evm_circuit::{
        param::{EVM_LOOKUP_COLS, MAX_STEP_HEIGHT, N_PHASE2_COLUMNS, STEP_WIDTH},
        step::{ExecutionState, Step},
        table::Table,
        util::{
            constraint_builder::{BaseConstraintBuilder, ConstrainBuilderCommon, EVMConstraintBuilder},
            rlc, CellType,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    table::LookupTable,
    util::{query_expression, Challenges, Expr},
};

use eth_types::{evm_unimplemented, Field, ToLittleEndian};
use gadgets::util::not;
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Layouter, Region, Value},
    plonk::{
        Advice, Column, ConstraintSystem, Error, Expression, FirstPhase, Fixed, SecondPhase,
        Selector, ThirdPhase, VirtualCells,
    },
    poly::Rotation,
};
use std::{
    collections::{HashMap},
    iter,
};
use std::collections::BTreeMap;
use halo2_proofs::plonk::Assigned;
use strum::EnumCount;

// TODO: "refactor this later"
mod end_inner_block;
mod error_code_store;
mod error_invalid_creation_code;
mod error_oog_account_access;
mod error_oog_create2;
mod error_oog_dynamic_memory;
mod error_oog_memory_copy;
mod error_oog_sha3;
mod error_precompile_failed;

mod common_begin_tx;
mod common_block_ctx;
mod common_dummy;
mod common_end_block;
mod common_end_tx;
mod error_invalid_jump;
mod error_invalid_opcode;
mod error_oog_call;
mod error_oog_constant;
mod error_oog_exp;
mod error_oog_log;
mod error_oog_sload_sstore;
mod error_oog_static_memory;
mod error_return_data_oo_bound;
mod error_stack;
mod error_write_protection;
mod evm_address;
mod evm_balance;
mod evm_blockhash;
mod evm_calldatacopy;
mod evm_calldataload;
mod evm_calldatasize;
mod evm_caller;
mod evm_callop;
mod evm_callvalue;
mod evm_chainid;
mod evm_codecopy;
mod evm_codesize;
mod evm_extcodecopy;
mod evm_extcodehash;
mod evm_extcodesize;
mod evm_gas;
mod evm_gasprice;
mod evm_keccak256;
mod evm_log;
mod evm_msize;
mod evm_origin;
mod evm_pc;
mod evm_return_revert;
mod evm_returndatacopy;
mod evm_returndatasize;
mod evm_selfbalance;
mod evm_sload;
mod evm_sstore;
mod evm_stop;
mod wasm_bin;
mod wasm_break;
mod wasm_call;
mod wasm_const;
mod wasm_conversion;
mod wasm_drop;
mod wasm_end;
mod wasm_global;
// mod wasm_load;
mod wasm_local;
mod wasm_rel;
mod wasm_select;
// mod wasm_store;
mod wasm_test;
mod wasm_unary;

use common_begin_tx::CommonBeginTxGadget;
// use common_block_ctx::CommonBlockCtxGadget;
use common_dummy::CommonDummyGadget;
use common_end_block::CommonEndBlockGadget;
use common_end_tx::CommonEndTxGadget;
use error_invalid_jump::ErrorInvalidJumpGadget;
use error_invalid_opcode::ErrorInvalidOpcodeGadget;
use error_oog_call::ErrorOOGCallGadget;
use error_oog_constant::ErrorOOGConstantGadget;
use error_oog_exp::ErrorOOGExpGadget;
use error_oog_log::ErrorOOGLogGadget;
use error_oog_sload_sstore::ErrorOOGSloadSstoreGadget;
// use error_oog_static_memory::ErrorOOGStaticMemoryGadget;
use error_return_data_oo_bound::ErrorReturnDataOutOfBoundGadget;
use error_stack::ErrorStackGadget;
use error_write_protection::ErrorWriteProtectionGadget;
use evm_address::EvmAddressGadget;
use evm_balance::EvmBalanceGadget;
use evm_blockhash::EvmBlockHashGadget;
use evm_calldatacopy::EvmCallDataCopyGadget;
use evm_calldataload::EvmCallDataLoadGadget;
use evm_calldatasize::EvmCallDataSizeGadget;
use evm_caller::EvmCallerGadget;
use evm_callop::EvmCallOpGadget;
use evm_callvalue::EvmCallValueGadget;
use evm_chainid::EvmChainIdGadget;
use evm_codecopy::EvmCodeCopyGadget;
use evm_codesize::EvmCodeSizeGadget;
use evm_extcodecopy::EvmExtCodeCopyGadget;
use evm_extcodehash::EvmExtCodeHashGadget;
use evm_extcodesize::EvmExtCodeSizeGadget;
use evm_gas::EvmGasGadget;
use evm_gasprice::EvmGasPriceGadget;
use evm_keccak256::EvmKeccak256Gadget;
use evm_log::EvmLogGadget;
use evm_msize::EvmMsizeGadget;
use evm_origin::EvmOriginGadget;
use evm_pc::EvmPcGadget;
use evm_return_revert::EvmReturnRevertGadget;
use evm_returndatacopy::EvmReturnDataCopyGadget;
use evm_returndatasize::EvmReturnDataSizeGadget;
use evm_selfbalance::EvmSelfBalanceGadget;
use evm_sload::EvmSloadGadget;
use evm_sstore::EvmSstoreGadget;
use evm_stop::EvmStopGadget;
use wasm_bin::WasmBinGadget;
use wasm_break::WasmBreakGadget;
use wasm_call::WasmCallGadget;
use wasm_const::WasmConstGadget;
use wasm_conversion::WasmConversionGadget;
use wasm_drop::WasmDropGadget;
use wasm_end::WasmEndGadget;
use wasm_global::WasmGlobalGadget;
// use wasm_load::WasmLoadGadget;
use wasm_local::WasmLocalGadget;
// use wasm_rel::WasmRelGadget;
use wasm_select::WasmSelectGadget;
// use wasm_store::WasmStoreGadget;
use wasm_test::WasmTestGadget;
use wasm_unary::WasmUnaryGadget;
use crate::evm_circuit::EvmCircuitExports;
use crate::evm_circuit::wasm::end_inner_block::EndInnerBlockGadget;
use crate::evm_circuit::wasm::error_code_store::ErrorCodeStoreGadget;
use crate::evm_circuit::wasm::error_invalid_creation_code::ErrorInvalidCreationCodeGadget;
use crate::evm_circuit::wasm::error_precompile_failed::ErrorPrecompileFailedGadget;
use crate::table::{RwTableTag, TxReceiptFieldTag};

use once_cell::sync::Lazy;
use bus_mapping::util::read_env_var;
use crate::witness::{Rw};

pub(crate) static CHECK_RW_LOOKUP: Lazy<bool> =
    Lazy::new(|| read_env_var("CHECK_RW_LOOKUP", true));

pub(crate) trait ExecutionGadget<F: FieldExt> {
    const NAME: &'static str;

    const EXECUTION_STATE: ExecutionState;

    fn configure(cb: &mut EVMConstraintBuilder<F>) -> Self;

    fn assign_exec_step(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        block: &Block<F>,
        transaction: &Transaction,
        call: &Call,
        step: &ExecStep,
    ) -> Result<(), Error>;
}

#[derive(Clone, Debug)]
pub(crate) struct ExecutionConfig<F> {
    // EVM Circuit selector, which enables all usable rows.  The rows where this selector is
    // disabled won't verify any constraint (they can be unused rows or rows with blinding
    // factors).
    q_usable: Selector,
    // Dynamic selector that is enabled at the rows where each assigned execution step starts (a
    // step has dynamic height).
    q_step: Column<Advice>,
    // Column to hold constant values used for copy constraints
    constants: Column<Fixed>,
    num_rows_until_next_step: Column<Advice>,
    num_rows_inv: Column<Advice>,
    // Selector enabled in the row where the first execution step starts.
    q_step_first: Selector,
    // Selector enabled in the row where the last execution step starts.
    q_step_last: Selector,
    advices: [Column<Advice>; STEP_WIDTH],
    step: Step<F>,
    pub(crate) height_map: HashMap<ExecutionState, usize>,
    stored_expressions_map: HashMap<ExecutionState, Vec<StoredExpression<F>>>,
    instrument: Instrument,

    // Common Gadgets
    common_begin_tx: Box<CommonBeginTxGadget<F>>,
    // common_block_ctx: Box<CommonBlockCtxGadget<F>>,
    // common_dummy: Box<CommonDummyGadget<F>>,
    common_end_block: Box<CommonEndBlockGadget<F>>,
    common_end_inner_block: Box<EndInnerBlockGadget<F>>,
    common_end_tx: Box<CommonEndTxGadget<F>>,

    // Error Gadgets
    error_oog_call: Box<ErrorOOGCallGadget<F>>,
    error_oog_constant: Box<ErrorOOGConstantGadget<F>>,
    error_oog_exp: Box<ErrorOOGExpGadget<F>>,
    error_oog_memory_copy: Box<CommonDummyGadget<F, 0, 0, { ExecutionState::ErrorOutOfGasMemoryCopy }>>,
    error_oog_sload_sstore: Box<ErrorOOGSloadSstoreGadget<F>>,
    error_oog_static_memory_gadget: Box<CommonDummyGadget<F, 0, 0, { ExecutionState::ErrorOutOfGasStaticMemoryExpansion }>>,
    error_stack: Box<ErrorStackGadget<F>>,
    error_write_protection: Box<ErrorWriteProtectionGadget<F>>,
    error_oog_dynamic_memory_gadget: Box<CommonDummyGadget<F, 0, 0, { ExecutionState::ErrorOutOfGasDynamicMemoryExpansion }>>,
    error_oog_log: Box<ErrorOOGLogGadget<F>>,
    error_oog_account_access: Box<CommonDummyGadget<F, 0, 0, { ExecutionState::ErrorOutOfGasAccountAccess }>>,
    error_oog_sha3: Box<CommonDummyGadget<F, 0, 0, { ExecutionState::ErrorOutOfGasSHA3 }>>,
    error_oog_create2: Box<CommonDummyGadget<F, 0, 0, { ExecutionState::ErrorOutOfGasCREATE }>>,
    error_code_store: Box<ErrorCodeStoreGadget<F>>,
    #[cfg(not(feature = "scroll"))]
    error_oog_self_destruct: Box<CommonDummyGadget<F, 0, 0, { ExecutionState::ErrorOutOfGasSELFDESTRUCT }>>,
    error_invalid_jump: Box<ErrorInvalidJumpGadget<F>>,
    error_invalid_opcode: Box<ErrorInvalidOpcodeGadget<F>>,
    error_invalid_creation_code: Box<ErrorInvalidCreationCodeGadget<F>>,
    error_precompile_failed: Box<ErrorPrecompileFailedGadget<F>>,
    error_return_data_out_of_bound: Box<ErrorReturnDataOutOfBoundGadget<F>>,

    // EVM Gadgets
    evm_address: Box<EvmAddressGadget<F>>,
    evm_balance: Box<EvmBalanceGadget<F>>,
    evm_blockhash: Box<EvmBlockHashGadget<F>>,
    evm_calldatacopy: Box<EvmCallDataCopyGadget<F>>,
    evm_calldataload: Box<EvmCallDataLoadGadget<F>>,
    evm_calldatasize: Box<EvmCallDataSizeGadget<F>>,
    evm_caller: Box<EvmCallerGadget<F>>,
    evm_callop: Box<EvmCallOpGadget<F>>,
    evm_callvalue: Box<EvmCallValueGadget<F>>,
    evm_chainid: Box<EvmChainIdGadget<F>>,
    evm_codecopy: Box<EvmCodeCopyGadget<F>>,
    evm_codesize: Box<EvmCodeSizeGadget<F>>,
    evm_extcodecopy: Box<EvmExtCodeCopyGadget<F>>,
    evm_extcodehash: Box<EvmExtCodeHashGadget<F>>,
    evm_extcodesize: Box<EvmExtCodeSizeGadget<F>>,
    evm_gas: Box<EvmGasGadget<F>>,
    evm_gasprice: Box<EvmGasPriceGadget<F>>,
    evm_keccak256: Box<EvmKeccak256Gadget<F>>,
    evm_log: Box<EvmLogGadget<F>>,
    evm_msize: Box<EvmMsizeGadget<F>>,
    evm_origin: Box<EvmOriginGadget<F>>,
    evm_pc: Box<EvmPcGadget<F>>,
    evm_return_revert: Box<EvmReturnRevertGadget<F>>,
    evm_returndatacopy: Box<EvmReturnDataCopyGadget<F>>,
    evm_returndatasize: Box<EvmReturnDataSizeGadget<F>>,
    evm_selfbalance: Box<EvmSelfBalanceGadget<F>>,
    evm_sload: Box<EvmSloadGadget<F>>,
    evm_sstore: Box<EvmSstoreGadget<F>>,
    evm_stop: Box<EvmStopGadget<F>>,

    // WASM Gadgets
    wasm_bin: Box<WasmBinGadget<F>>,
    wasm_break: Box<WasmBreakGadget<F>>,
    wasm_call: Box<WasmCallGadget<F>>,
    wasm_const: Box<WasmConstGadget<F>>,
    wasm_conversion: Box<WasmConversionGadget<F>>,
    wasm_drop: Box<WasmDropGadget<F>>,
    wasm_end: Box<WasmEndGadget<F>>,
    wasm_global: Box<WasmGlobalGadget<F>>,
    // wasm_load: Box<WasmLoadGadget<F>>,
    wasm_local: Box<WasmLocalGadget<F>>,
    // wasm_rel: Box<WasmRelGadget<F>>,
    wasm_select: Box<WasmSelectGadget<F>>,
    // wasm_store: Box<WasmStoreGadget<F>>,
    wasm_test: Box<WasmTestGadget<F>>,
    wasm_unary: Box<WasmUnaryGadget<F>>,
}

impl<F: Field> ExecutionConfig<F> {
    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::redundant_closure_call)]
    pub(crate) fn configure(
        meta: &mut ConstraintSystem<F>,
        challenges: Challenges<Expression<F>>,
        fixed_table: &dyn LookupTable<F>,
        byte_table: &dyn LookupTable<F>,
        tx_table: &dyn LookupTable<F>,
        rw_table: &dyn LookupTable<F>,
        bytecode_table: &dyn LookupTable<F>,
        block_table: &dyn LookupTable<F>,
        copy_table: &dyn LookupTable<F>,
        keccak_table: &dyn LookupTable<F>,
        exp_table: &dyn LookupTable<F>,
    ) -> Self {
        let mut instrument = Instrument::default();
        let q_usable = meta.complex_selector();
        let q_step = meta.advice_column();
        let constants = meta.fixed_column();
        meta.enable_constant(constants);
        let num_rows_until_next_step = meta.advice_column();
        let num_rows_inv = meta.advice_column();
        let q_step_first = meta.complex_selector();
        let q_step_last = meta.complex_selector();

        let advices = [(); STEP_WIDTH]
            .iter()
            .enumerate()
            .map(|(n, _)| {
                if n < EVM_LOOKUP_COLS {
                    meta.advice_column_in(ThirdPhase)
                } else if n < EVM_LOOKUP_COLS + N_PHASE2_COLUMNS {
                    meta.advice_column_in(SecondPhase)
                } else {
                    meta.advice_column_in(FirstPhase)
                }
            })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        let step_curr = Step::new(meta, advices, 0, false);
        let mut height_map = HashMap::new();

        meta.create_gate("Constrain execution state", |meta| {
            let q_usable = meta.query_selector(q_usable);
            let q_step = meta.query_advice(q_step, Rotation::cur());
            let q_step_first = meta.query_selector(q_step_first);
            let q_step_last = meta.query_selector(q_step_last);

            let execution_state_selector_constraints = step_curr.state.execution_state.configure();

            // NEW: Enabled, this will break hand crafted tests, maybe we can remove them?
            let first_step_check = {
                let begin_tx_end_block_selector = step_curr
                    .execution_state_selector([ExecutionState::BeginTx, ExecutionState::EndBlock]);
                iter::once((
                    "First step should be BeginTx or EndBlock",
                    q_step_first * (1.expr() - begin_tx_end_block_selector),
                ))
            };

            let last_step_check = {
                let end_block_selector =
                    step_curr.execution_state_selector([ExecutionState::EndBlock]);
                iter::once((
                    "Last step should be EndBlock",
                    q_step_last * (1.expr() - end_block_selector),
                ))
            };

            execution_state_selector_constraints
                .into_iter()
                .map(move |(name, poly)| (name, q_usable.clone() * q_step.clone() * poly))
                .chain(first_step_check)
                .chain(last_step_check)
        });

        meta.create_gate("q_step", |meta| {
            let q_usable = meta.query_selector(q_usable);
            let q_step_first = meta.query_selector(q_step_first);
            let q_step_last = meta.query_selector(q_step_last);
            let q_step = meta.query_advice(q_step, Rotation::cur());
            let num_rows_left_cur = meta.query_advice(num_rows_until_next_step, Rotation::cur());
            let num_rows_left_next = meta.query_advice(num_rows_until_next_step, Rotation::next());
            let num_rows_left_inverse = meta.query_advice(num_rows_inv, Rotation::cur());

            let mut cb = BaseConstraintBuilder::default();
            // q_step needs to be enabled on the first row
            // rw_counter starts at 1
            cb.condition(q_step_first, |cb| {
                cb.require_equal("q_step == 1", q_step.clone(), 1.expr());
                cb.require_equal(
                    "rw_counter is initialized to be 1",
                    step_curr.state.rw_counter.expr(),
                    1.expr(),
                )
            });
            // For every step, is_create and is_root are boolean.
            cb.condition(q_step.clone(), |cb| {
                cb.require_boolean(
                    "step.is_create is boolean",
                    step_curr.state.is_create.expr(),
                );
                cb.require_boolean("step.is_root is boolean", step_curr.state.is_root.expr());
            });
            // q_step needs to be enabled on the last row
            cb.condition(q_step_last, |cb| {
                cb.require_equal("q_step == 1", q_step.clone(), 1.expr());
            });
            // Except when step is enabled, the step counter needs to decrease by 1
            cb.condition(1.expr() - q_step.clone(), |cb| {
                cb.require_equal(
                    "num_rows_left_cur := num_rows_left_next + 1",
                    num_rows_left_cur.clone(),
                    num_rows_left_next + 1.expr(),
                );
            });
            // Enforce that q_step := num_rows_until_next_step == 0
            let is_zero = 1.expr() - (num_rows_left_cur.clone() * num_rows_left_inverse.clone());
            cb.require_zero(
                "num_rows_left_cur * is_zero == 0",
                num_rows_left_cur * is_zero.clone(),
            );
            cb.require_zero(
                "num_rows_left_inverse * is_zero == 0",
                num_rows_left_inverse * is_zero.clone(),
            );
            cb.require_equal("q_step == is_zero", q_step, is_zero);
            // On each usable row
            cb.gate(q_usable)
        });

        let mut stored_expressions_map = HashMap::new();

        macro_rules! configure_gadget {
            () => {
                // We create each gadget in a closure so that the stack required to hold
                // the gadget value before being copied to the box is freed immediately after
                // the boxed gadget is returned.
                // We put each gadget in a box so that they stay in the heap to keep
                // ExecutionConfig at a managable size.
                (|| {
                    Box::new(Self::configure_gadget(
                        meta,
                        advices,
                        q_usable,
                        q_step,
                        num_rows_until_next_step,
                        q_step_first,
                        q_step_last,
                        &challenges,
                        &step_curr,
                        &mut height_map,
                        &mut stored_expressions_map,
                        &mut instrument,
                    ))
                })()
            };
        }

        let cell_manager = step_curr.cell_manager.clone();

        let config = Self {
            q_usable,
            q_step,
            constants,
            num_rows_until_next_step,
            num_rows_inv,
            q_step_first,
            q_step_last,
            advices,

            common_begin_tx: configure_gadget!(),
            // common_block_ctx: configure_gadget!(),
            // common_dummy: configure_gadget!(),
            common_end_block: configure_gadget!(),
            common_end_inner_block: configure_gadget!(),
            common_end_tx: configure_gadget!(),
            error_oog_constant: configure_gadget!(),
            error_oog_static_memory_gadget: configure_gadget!(),
            error_stack: configure_gadget!(),
            error_oog_dynamic_memory_gadget: configure_gadget!(),
            error_oog_log: configure_gadget!(),
            error_oog_sload_sstore: configure_gadget!(),
            error_oog_call: configure_gadget!(),
            error_oog_memory_copy: configure_gadget!(),
            error_oog_account_access: configure_gadget!(),
            error_oog_sha3: configure_gadget!(),
            error_oog_exp: configure_gadget!(),
            error_oog_create2: configure_gadget!(),
            #[cfg(not(feature = "scroll"))]
            error_oog_self_destruct: configure_gadget!(),
            error_code_store: configure_gadget!(),
            error_invalid_jump: configure_gadget!(),
            error_invalid_opcode: configure_gadget!(),
            error_write_protection: configure_gadget!(),
            error_invalid_creation_code: configure_gadget!(),
            error_return_data_out_of_bound: configure_gadget!(),
            error_precompile_failed: configure_gadget!(),
            evm_address: configure_gadget!(),
            evm_balance: configure_gadget!(),
            evm_blockhash: configure_gadget!(),
            evm_calldatacopy: configure_gadget!(),
            evm_calldataload: configure_gadget!(),
            evm_calldatasize: configure_gadget!(),
            evm_caller: configure_gadget!(),
            evm_callop: configure_gadget!(),
            evm_callvalue: configure_gadget!(),
            evm_chainid: configure_gadget!(),
            evm_codecopy: configure_gadget!(),
            evm_codesize: configure_gadget!(),
            evm_extcodecopy: configure_gadget!(),
            evm_extcodehash: configure_gadget!(),
            evm_extcodesize: configure_gadget!(),
            evm_gas: configure_gadget!(),
            evm_gasprice: configure_gadget!(),
            evm_keccak256: configure_gadget!(),
            evm_log: configure_gadget!(),
            evm_msize: configure_gadget!(),
            evm_origin: configure_gadget!(),
            evm_pc: configure_gadget!(),
            evm_return_revert: configure_gadget!(),
            evm_returndatacopy: configure_gadget!(),
            evm_returndatasize: configure_gadget!(),
            evm_selfbalance: configure_gadget!(),
            evm_sload: configure_gadget!(),
            evm_sstore: configure_gadget!(),
            evm_stop: configure_gadget!(),
            wasm_bin: configure_gadget!(),
            wasm_break: configure_gadget!(),
            wasm_call: configure_gadget!(),
            wasm_const: configure_gadget!(),
            wasm_conversion: configure_gadget!(),
            wasm_drop: configure_gadget!(),
            wasm_end: configure_gadget!(),
            wasm_global: configure_gadget!(),
            // wasm_load: configure_gadget!(),
            wasm_local: configure_gadget!(),
            // wasm_rel: configure_gadget!(),
            wasm_select: configure_gadget!(),
            // wasm_store: configure_gadget!(),
            wasm_test: configure_gadget!(),
            wasm_unary: configure_gadget!(),

            // step and presets
            step: step_curr,
            height_map,
            stored_expressions_map,
            instrument,
        };

        Self::configure_lookup(
            meta,
            fixed_table,
            byte_table,
            tx_table,
            rw_table,
            bytecode_table,
            block_table,
            copy_table,
            keccak_table,
            exp_table,
            &challenges,
            &cell_manager,
        );
        config
    }

    pub(crate) fn instrument(&self) -> &Instrument {
        &self.instrument
    }

    #[allow(clippy::too_many_arguments)]
    fn configure_gadget<G: ExecutionGadget<F>>(
        meta: &mut ConstraintSystem<F>,
        advices: [Column<Advice>; STEP_WIDTH],
        q_usable: Selector,
        q_step: Column<Advice>,
        num_rows_until_next_step: Column<Advice>,
        q_step_first: Selector,
        q_step_last: Selector,
        challenges: &Challenges<Expression<F>>,
        step_curr: &Step<F>,
        height_map: &mut HashMap<ExecutionState, usize>,
        stored_expressions_map: &mut HashMap<ExecutionState, Vec<StoredExpression<F>>>,
        instrument: &mut Instrument,
    ) -> G {
        // Configure the gadget with the max height first so we can find out the actual
        // height
        let height = {
            let dummy_step_next = Step::new(meta, advices, MAX_STEP_HEIGHT, true);
            let mut cb = EVMConstraintBuilder::new(
                step_curr.clone(),
                dummy_step_next,
                challenges,
                G::EXECUTION_STATE,
            );
            G::configure(&mut cb);
            let (_, _, height) = cb.build();
            height
        };

        // Now actually configure the gadget with the correct minimal height
        let step_next = &Step::new(meta, advices, height, true);
        let mut cb = EVMConstraintBuilder::new(
            step_curr.clone(),
            step_next.clone(),
            challenges,
            G::EXECUTION_STATE,
        );

        let gadget = G::configure(&mut cb);

        Self::configure_gadget_impl(
            meta,
            q_usable,
            q_step,
            num_rows_until_next_step,
            q_step_first,
            q_step_last,
            step_curr,
            step_next,
            height_map,
            stored_expressions_map,
            instrument,
            G::NAME,
            G::EXECUTION_STATE,
            height,
            cb,
        );

        gadget
    }

    #[allow(clippy::too_many_arguments)]
    fn configure_gadget_impl(
        meta: &mut ConstraintSystem<F>,
        q_usable: Selector,
        q_step: Column<Advice>,
        num_rows_until_next_step: Column<Advice>,
        q_step_first: Selector,
        q_step_last: Selector,
        _step_curr: &Step<F>,
        _step_next: &Step<F>,
        height_map: &mut HashMap<ExecutionState, usize>,
        stored_expressions_map: &mut HashMap<ExecutionState, Vec<StoredExpression<F>>>,
        instrument: &mut Instrument,
        name: &'static str,
        execution_state: ExecutionState,
        height: usize,
        mut cb: EVMConstraintBuilder<F>,
    ) {
        // Enforce the step height for this opcode
        let num_rows_until_next_step_next = query_expression(meta, |meta| {
            meta.query_advice(num_rows_until_next_step, Rotation::next())
        });
        cb.require_equal(
            "num_rows_until_next_step_next := height - 1",
            num_rows_until_next_step_next,
            (height - 1).expr(),
        );

        instrument.on_gadget_built(execution_state, &cb);

        let (constraints, stored_expressions, _) = cb.build();
        debug_assert!(
            !height_map.contains_key(&execution_state),
            "execution state already configured"
        );

        height_map.insert(execution_state, height);
        debug_assert!(
            !stored_expressions_map.contains_key(&execution_state),
            "execution state already configured"
        );
        stored_expressions_map.insert(execution_state, stored_expressions);

        // Enforce the logic for this opcode
        let sel_step: &dyn Fn(&mut VirtualCells<F>) -> Expression<F> =
            &|meta| meta.query_advice(q_step, Rotation::cur());
        let sel_step_first: &dyn Fn(&mut VirtualCells<F>) -> Expression<F> =
            &|meta| meta.query_selector(q_step_first);
        let sel_step_last: &dyn Fn(&mut VirtualCells<F>) -> Expression<F> =
            &|meta| meta.query_selector(q_step_last);
        let sel_not_step_last: &dyn Fn(&mut VirtualCells<F>) -> Expression<F> = &|meta| {
            meta.query_advice(q_step, Rotation::cur()) * not::expr(meta.query_selector(q_step_last))
        };

        for (selector, constraints) in [
            (sel_step, constraints.step),
            (sel_step_first, constraints.step_first),
            (sel_step_last, constraints.step_last),
            (sel_not_step_last, constraints.not_step_last),
        ] {
            if !constraints.is_empty() {
                meta.create_gate(name, |meta| {
                    let q_usable = meta.query_selector(q_usable);
                    let selector = selector(meta);
                    constraints.into_iter().map(move |(name, constraint)| {
                        (name, q_usable.clone() * selector.clone() * constraint)
                    })
                });
            }
        }

        // Enforce the state transitions for this opcode
        // meta.create_gate("Constrain state machine transitions", |meta| {
        //     let q_usable = meta.query_selector(q_usable);
        //     let q_step = meta.query_advice(q_step, Rotation::cur());
        //     let q_step_last = meta.query_selector(q_step_last);
        //
        //     // ExecutionState transition should be correct.
        //     iter::empty()
        //         .chain(
        //             IntoIterator::into_iter([
        //                 (
        //                     "EndTx can only transit to BeginTx or EndBlock",
        //                     ExecutionState::EndTx,
        //                     vec![ExecutionState::BeginTx, ExecutionState::EndBlock],
        //                 ),
        //                 (
        //                     "EndBlock can only transit to EndBlock",
        //                     ExecutionState::EndBlock,
        //                     vec![ExecutionState::EndBlock],
        //                 ),
        //             ])
        //             .filter(move |(_, from, _)| *from == execution_state)
        //             .map(|(_, _, to)| 1.expr() - step_next.execution_state_selector(to)),
        //         )
        //         .chain(
        //             IntoIterator::into_iter([
        //                 (
        //                     "Only EndTx can transit to BeginTx",
        //                     ExecutionState::BeginTx,
        //                     vec![ExecutionState::EndTx],
        //                 ),
        //                 (
        //                     "Only ExecutionState which halts or BeginTx can transit to EndTx",
        //                     ExecutionState::EndTx,
        //                     ExecutionState::iter()
        //                         .filter(ExecutionState::halts)
        //                         .chain(iter::once(ExecutionState::BeginTx))
        //                         .collect(),
        //                 ),
        //                 (
        //                     "Only EndTx or EndBlock can transit to EndBlock",
        //                     ExecutionState::EndBlock,
        //                     vec![ExecutionState::EndTx, ExecutionState::EndBlock],
        //                 ),
        //             ])
        //             .filter(move |(_, _, from)| !from.contains(&execution_state))
        //             .map(|(_, to, _)| step_next.execution_state_selector([to])),
        //         )
        //         // Accumulate all state transition checks.
        //         // This can be done because all summed values are enforced to be boolean.
        //         .reduce(|accum, poly| accum + poly)
        //         .map(move |poly| {
        //             q_usable.clone()
        //                 * q_step.clone()
        //                 * (1.expr() - q_step_last.clone())
        //                 * step_curr.execution_state_selector([execution_state])
        //                 * poly
        //         })
        // });
    }

    #[allow(clippy::too_many_arguments)]
    fn configure_lookup(
        meta: &mut ConstraintSystem<F>,
        fixed_table: &dyn LookupTable<F>,
        byte_table: &dyn LookupTable<F>,
        tx_table: &dyn LookupTable<F>,
        rw_table: &dyn LookupTable<F>,
        bytecode_table: &dyn LookupTable<F>,
        block_table: &dyn LookupTable<F>,
        copy_table: &dyn LookupTable<F>,
        keccak_table: &dyn LookupTable<F>,
        exp_table: &dyn LookupTable<F>,
        challenges: &Challenges<Expression<F>>,
        cell_manager: &CellManager<F>,
    ) {
        for column in cell_manager.columns().iter() {
            if let CellType::Lookup(table) = column.cell_type {
                let name = format!("{:?}", table);
                meta.lookup_any(Box::leak(name.into_boxed_str()), |meta| {
                    let table_expressions = match table {
                        Table::Fixed => fixed_table,
                        Table::Tx => tx_table,
                        Table::Rw => rw_table,
                        Table::Bytecode => bytecode_table,
                        Table::Block => block_table,
                        Table::Copy => copy_table,
                        Table::Keccak => keccak_table,
                        Table::Exp => exp_table,
                    }
                    .table_exprs(meta);
                    vec![(
                        column.expr(),
                        rlc::expr(&table_expressions, challenges.lookup_input()),
                    )]
                });
            }
        }
        for column in cell_manager.columns().iter() {
            if let CellType::LookupByte = column.cell_type {
                meta.lookup_any("Byte lookup", |meta| {
                    let byte_table_expression = byte_table.table_exprs(meta)[0].clone();
                    vec![(column.expr(), byte_table_expression)]
                });
            }
        }
    }

    pub fn get_num_rows_required(&self, block: &Block<F>) -> usize {
        // Start at 1 so we can be sure there is an unused `next` row available
        let mut num_rows = 1;
        let evm_rows = block.circuits_params.max_evm_rows;
        if evm_rows == 0 {
            for transaction in &block.txs {
                for step in &transaction.steps {
                    num_rows += step.execution_state.get_step_height();
                }
            }
            num_rows += 1; // EndBlock
        } else {
            num_rows = block.circuits_params.max_evm_rows;
        }
        num_rows
    }

    /// Assign columns related to step counter
    fn assign_q_step(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        height: usize,
    ) -> Result<(), Error> {
        // Name Advice columns
        for idx in 0..height {
            let offset = offset + idx;
            self.q_usable.enable(region, offset)?;
            region.assign_advice(
                || "step selector",
                self.q_step,
                offset,
                || Value::known(if idx == 0 { F::one() } else { F::zero() }),
            )?;
            let value = if idx == 0 {
                F::zero()
            } else {
                F::from((height - idx) as u64)
            };
            region.assign_advice(
                || "step height",
                self.num_rows_until_next_step,
                offset,
                || Value::known(value),
            )?;
            region.assign_advice(
                || "step height inv",
                self.num_rows_inv,
                offset,
                || Value::known(value.invert().unwrap_or(F::zero())),
            )?;
        }
        Ok(())
    }

    /// Assign block
    /// When exact is enabled, assign exact steps in block without padding for
    /// unit test purpose
    pub fn assign_block(
        &self,
        layouter: &mut impl Layouter<F>,
        block: &Block<F>,
        challenges: &Challenges<Value<F>>,
    ) -> Result<EvmCircuitExports<Assigned<F>>, Error> {
        let mut is_first_time = true;

        layouter.assign_region(
            || "Execution step",
            |mut region| {
                if is_first_time {
                    is_first_time = false;
                    region.assign_advice(
                        || "step selector",
                        self.q_step,
                        self.get_num_rows_required(block) - 1,
                        || Value::known(F::zero()),
                    )?;
                    return Ok(());
                }
                let mut offset = 0;

                // Annotate the EVMCircuit columns within it's single region.
                self.annotate_circuit(&mut region);

                self.q_step_first.enable(&mut region, offset)?;

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

                let evm_rows = block.circuits_params.max_evm_rows;
                let no_padding = evm_rows == 0;

                // part1: assign real steps
                loop {
                    let (transaction, call, step) = steps.next().expect("should not be empty");
                    let next = steps.peek();
                    if next.is_none() {
                        break;
                    }
                    let height = step.execution_state.get_step_height();

                    // Assign the step witness
                    if step.execution_state == ExecutionState::EndTx {
                        let mut tx = transaction.clone();
                        tx.call_data.clear();
                        tx.calls.clear();
                        tx.steps.clear();
                        tx.rlp_signed.clear();
                        tx.rlp_unsigned.clear();
                        let total_gas = {
                            let gas_used = tx.gas - step.gas_left;
                            let current_cumulative_gas_used: u64 = if tx.id == 1 {
                                0
                            } else {
                                // first transaction needs TxReceiptFieldTag::COUNT(3) lookups
                                // to tx receipt,
                                // while later transactions need 4 (with one extra cumulative
                                // gas read) lookups
                                let rw = &block.rws[(
                                    RwTableTag::TxReceipt,
                                    (tx.id - 2) * (TxReceiptFieldTag::COUNT + 1) + 2,
                                )];
                                rw.receipt_value()
                            };
                            current_cumulative_gas_used + gas_used
                        };
                        log::info!(
                            "offset {} tx_num {} total_gas {} assign last step {:?} of tx {:?}",
                            offset,
                            tx.id,
                            total_gas,
                            step,
                            tx
                        );
                    }
                    self.assign_exec_step(
                        &mut region,
                        offset,
                        block,
                        transaction,
                        call,
                        step,
                        height,
                        next.copied(),
                        challenges,
                    )?;

                    // q_step logic
                    self.assign_q_step(&mut region, offset, height)?;

                    offset += height;
                }

                // part2: assign non-last EndBlock steps when padding needed
                if !no_padding {
                    let height = ExecutionState::EndBlock.get_step_height();
                    debug_assert_eq!(height, 1);
                    // 1 for EndBlock(last), 1 for "part 4" cells
                    let last_row = evm_rows - 2;
                    log::trace!(
                        "assign non-last EndBlock in range [{},{})",
                        offset,
                        last_row
                    );
                    if offset > last_row {
                        log::error!(
                            "evm circuit row not enough, offset: {}, max_evm_rows: {}",
                            offset,
                            evm_rows
                        );
                        return Err(Error::Synthesis);
                    }
                    self.assign_same_exec_step_in_range(
                        &mut region,
                        offset,
                        last_row,
                        block,
                        &dummy_tx,
                        &last_call,
                        end_block_not_last,
                        height,
                        challenges,
                    )?;

                    for row_idx in offset..last_row {
                        self.assign_q_step(&mut region, row_idx, height)?;
                    }
                    offset = last_row;
                }

                // part3: assign the last EndBlock at offset `evm_rows - 1`
                let height = ExecutionState::EndBlock.get_step_height();
                debug_assert_eq!(height, 1);
                log::trace!("assign last EndBlock at offset {}", offset);
                self.assign_exec_step(
                    &mut region,
                    offset,
                    block,
                    &dummy_tx,
                    &last_call,
                    end_block_last,
                    height,
                    None,
                    challenges,
                )?;
                self.assign_q_step(&mut region, offset, height)?;
                // enable q_step_last
                self.q_step_last.enable(&mut region, offset)?;
                offset += height;

                // part4:
                // These are still referenced (but not used) in next rows
                region.assign_advice(
                    || "step height",
                    self.num_rows_until_next_step,
                    offset,
                    || Value::known(F::zero()),
                )?;
                region.assign_advice(
                    || "step height inv",
                    self.q_step,
                    offset,
                    || Value::known(F::zero()),
                )?;

                log::debug!("assign for region done at offset {}", offset);
                Ok(())
            },
        )?;

        log::debug!("assign_block done");

        let final_withdraw_root_cell = self
            .common_end_block
            .withdraw_root_assigned
            .borrow()
            .expect("withdraw_root cell should has been assigned");

        // sanity check
        let evm_rows = block.circuits_params.max_evm_rows;
        if evm_rows >= 2 {
            assert_eq!(final_withdraw_root_cell.row_offset, evm_rows - 2);
        }

        let withdraw_root_rlc = challenges
            .evm_word()
            .map(|r| rlc::value(&block.withdraw_root.to_le_bytes(), r));

        Ok(EvmCircuitExports {
            withdraw_root: (final_withdraw_root_cell, withdraw_root_rlc.into()),
        })
    }

    fn annotate_circuit(&self, region: &mut Region<F>) {
        let groups = [
            ("EVM_lookup_fixed", FIXED_TABLE_LOOKUPS),
            ("EVM_lookup_tx", TX_TABLE_LOOKUPS),
            ("EVM_lookup_rw", RW_TABLE_LOOKUPS),
            ("EVM_lookup_bytecode", BYTECODE_TABLE_LOOKUPS),
            ("EVM_lookup_block", BLOCK_TABLE_LOOKUPS),
            ("EVM_lookup_copy", COPY_TABLE_LOOKUPS),
            ("EVM_lookup_keccak", KECCAK_TABLE_LOOKUPS),
            ("EVM_lookup_exp", EXP_TABLE_LOOKUPS),
            ("EVM_adv_phase2", N_PHASE2_COLUMNS),
            ("EVM_copy", N_COPY_COLUMNS),
            ("EVM_lookup_byte", N_BYTE_LOOKUPS),
            ("EVM_adv_phase1", N_PHASE1_COLUMNS),
        ];
        let mut group_index = 0;
        let mut index = 0;
        for col in self.advices {
            let (name, length) = groups[group_index];
            region.name_column(|| format!("{}_{}", name, index), col);
            index += 1;
            if index >= length {
                index = 0;
                group_index += 1;
            }
        }

        region.name_column(|| "EVM_q_step", self.q_step);
        region.name_column(|| "EVM_num_rows_inv", self.num_rows_inv);
        region.name_column(|| "EVM_rows_until_next_step", self.num_rows_until_next_step);
        region.name_column(|| "Copy_Constr_const", self.constants);
    }

    #[allow(clippy::too_many_arguments)]
    fn assign_same_exec_step_in_range(
        &self,
        region: &mut Region<'_, F>,
        offset_begin: usize,
        offset_end: usize,
        block: &Block<F>,
        transaction: &Transaction,
        call: &Call,
        step: &ExecStep,
        height: usize,
        challenges: &Challenges<Value<F>>,
    ) -> Result<(), Error> {
        if offset_end <= offset_begin {
            return Ok(());
        }
        assert_eq!(height, 1);
        assert!(step.rw_indices.is_empty());
        assert!(matches!(step.execution_state, ExecutionState::EndBlock));

        // Disable access to next step deliberately for "repeatable" step
        let region = &mut CachedRegion::<'_, '_, F>::new(
            region,
            challenges,
            self.advices.to_vec(),
            1,
            offset_begin,
        );
        self.assign_exec_step_int(region, offset_begin, block, transaction, call, step)?;

        region.replicate_assignment_for_range(
            || format!("repeat {:?} rows", step.execution_state),
            offset_begin + 1,
            offset_end,
        )?;

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn assign_exec_step(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        block: &Block<F>,
        transaction: &Transaction,
        call: &Call,
        step: &ExecStep,
        height: usize,
        next: Option<(&Transaction, &Call, &ExecStep)>,
        challenges: &Challenges<Value<F>>,
    ) -> Result<(), Error> {
        if !matches!(step.execution_state, ExecutionState::EndBlock) {
            log::trace!(
                "assign_exec_step offset: {} state {:?} step: {:?} call: {:?}",
                offset,
                step.execution_state,
                step,
                call
            );
        }
        // Make the region large enough for the current step and the next step.
        // The next step's next step may also be accessed, so make the region large
        // enough for 3 steps.
        let region = &mut CachedRegion::<'_, '_, F>::new(
            region,
            challenges,
            self.advices.to_vec(),
            MAX_STEP_HEIGHT * 3,
            offset,
        );

        // Also set the witness of the next step.
        // These may be used in stored expressions and
        // so their witness values need to be known to be able
        // to correctly calculate the intermediate value.
        if let Some((transaction_next, call_next, step_next)) = next {
            self.assign_exec_step_int(
                region,
                offset + height,
                block,
                transaction_next,
                call_next,
                step_next,
            )?;
        }

        self.assign_exec_step_int(region, offset, block, transaction, call, step)
    }

    fn assign_exec_step_int(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        block: &Block<F>,
        transaction: &Transaction,
        call: &Call,
        step: &ExecStep,
    ) -> Result<(), Error> {
        self.step
            .assign_exec_step(region, offset, block, transaction, call, step)?;

        macro_rules! assign_exec_step {
            ($gadget:expr) => {
                $gadget.assign_exec_step(region, offset, block, transaction, call, step)?
            };
        }

        match step.execution_state {
            // internal states
            ExecutionState::BeginTx => assign_exec_step!(self.common_begin_tx),
            ExecutionState::EndBlock => assign_exec_step!(self.common_end_block),
            ExecutionState::EndInnerBlock => assign_exec_step!(self.common_end_inner_block),
            ExecutionState::EndTx => assign_exec_step!(self.common_end_tx),
            // WASM opcodes
            ExecutionState::WASM_BIN => assign_exec_step!(self.wasm_bin),
            ExecutionState::WASM_TEST => assign_exec_step!(self.wasm_test),
            ExecutionState::WASM_CONST => assign_exec_step!(self.wasm_const),
            ExecutionState::WASM_DROP => assign_exec_step!(self.wasm_drop),
            ExecutionState::WASM_GLOBAL => assign_exec_step!(self.wasm_global),
            ExecutionState::WASM_LOCAL => assign_exec_step!(self.wasm_local),
            ExecutionState::WASM_UNARY => assign_exec_step!(self.wasm_unary),
            ExecutionState::WASM_END => assign_exec_step!(self.wasm_end),
            ExecutionState::WASM_BREAK => assign_exec_step!(self.wasm_break),
            ExecutionState::WASM_CALL => assign_exec_step!(self.wasm_call),
            // opcode
            ExecutionState::SHA3 => assign_exec_step!(self.evm_keccak256),
            ExecutionState::ADDRESS => assign_exec_step!(self.evm_address),
            ExecutionState::BALANCE => assign_exec_step!(self.evm_balance),
            ExecutionState::CALL_OP => assign_exec_step!(self.evm_callop),
            ExecutionState::CALLDATACOPY => assign_exec_step!(self.evm_calldatacopy),
            ExecutionState::CALLDATALOAD => assign_exec_step!(self.evm_calldataload),
            ExecutionState::CALLDATASIZE => assign_exec_step!(self.evm_calldatasize),
            ExecutionState::CALLER => assign_exec_step!(self.evm_caller),
            ExecutionState::CALLVALUE => assign_exec_step!(self.evm_callvalue),
            ExecutionState::CHAINID => assign_exec_step!(self.evm_chainid),
            ExecutionState::CODECOPY => assign_exec_step!(self.evm_codecopy),
            ExecutionState::CODESIZE => assign_exec_step!(self.evm_codesize),
            // ExecutionState::EXTCODEHASH => assign_exec_step!(self.extcodehash_gadget),
            ExecutionState::EXTCODESIZE => assign_exec_step!(self.evm_extcodesize),
            // ExecutionState::GAS => assign_exec_step!(self.gas_gadget),
            ExecutionState::GASPRICE => assign_exec_step!(self.evm_gasprice),
            ExecutionState::LOG => assign_exec_step!(self.evm_log),
            // ExecutionState::MEMORY => assign_exec_step!(self.memory_gadget),
            ExecutionState::SLOAD => assign_exec_step!(self.evm_sload),
            // ExecutionState::MSIZE => assign_exec_step!(self.msize_gadget),
            ExecutionState::ORIGIN => assign_exec_step!(self.evm_origin),
            // ExecutionState::PC => assign_exec_step!(self.pc_gadget),
            ExecutionState::RETURN_REVERT => assign_exec_step!(self.evm_return_revert),
            // ExecutionState::RETURNDATASIZE => assign_exec_step!(self.returndatasize_gadget),
            // ExecutionState::RETURNDATACOPY => assign_exec_step!(self.returndatacopy_gadget),
            // ExecutionState::BLOCKCTXU64 => assign_exec_step!(self.block_ctx_u64_gadget),
            // ExecutionState::BLOCKCTXU160 => assign_exec_step!(self.block_ctx_u160_gadget),
            // ExecutionState::BLOCKCTXU256 => assign_exec_step!(self.block_ctx_u256_gadget),
            ExecutionState::BLOCKHASH => assign_exec_step!(self.evm_blockhash),
            ExecutionState::SELFBALANCE => assign_exec_step!(self.evm_selfbalance),
            // dummy gadgets
            ExecutionState::EXTCODECOPY => assign_exec_step!(self.evm_extcodecopy),
            // ExecutionState::CREATE => assign_exec_step!(self.create_gadget),
            // ExecutionState::CREATE2 => assign_exec_step!(self.create2_gadget),
            // ExecutionState::SELFDESTRUCT => assign_exec_step!(self.selfdestruct_gadget),
            // end of dummy gadgets
            // ExecutionState::SHA3 => assign_exec_step!(self.sha3_gadget),
            // ExecutionState::SHL_SHR => assign_exec_step!(self.shl_shr_gadget),
            // ExecutionState::SIGNEXTEND => assign_exec_step!(self.signextend_gadget),
            // ExecutionState::SLOAD => assign_exec_step!(self.sload_gadget),
            // ExecutionState::SSTORE => assign_exec_step!(self.sstore_gadget),
            // ExecutionState::STOP => assign_exec_step!(self.stop_gadget),
            // ExecutionState::SWAP => assign_exec_step!(self.swap_gadget),
            // dummy errors
            ExecutionState::ErrorOutOfGasStaticMemoryExpansion => {
                assign_exec_step!(self.error_oog_static_memory_gadget)
            }
            ExecutionState::ErrorOutOfGasConstant => {
                assign_exec_step!(self.error_oog_constant)
            }
            ExecutionState::ErrorOutOfGasCall => {
                assign_exec_step!(self.error_oog_call)
            }
            ExecutionState::ErrorOutOfGasDynamicMemoryExpansion => {
                assign_exec_step!(self.error_oog_dynamic_memory_gadget)
            }
            ExecutionState::ErrorOutOfGasLOG => {
                assign_exec_step!(self.error_oog_log)
            }
            ExecutionState::ErrorOutOfGasSloadSstore => {
                assign_exec_step!(self.error_oog_sload_sstore)
            }
            ExecutionState::ErrorOutOfGasMemoryCopy => {
                assign_exec_step!(self.error_oog_memory_copy)
            }
            ExecutionState::ErrorOutOfGasAccountAccess => {
                assign_exec_step!(self.error_oog_account_access)
            }
            ExecutionState::ErrorOutOfGasSHA3 => {
                assign_exec_step!(self.error_oog_sha3)
            }
            ExecutionState::ErrorOutOfGasEXP => {
                assign_exec_step!(self.error_oog_exp)
            }
            ExecutionState::ErrorOutOfGasCREATE => {
                assign_exec_step!(self.error_oog_create2)
            }
            ExecutionState::ErrorOutOfGasSELFDESTRUCT => {
                #[cfg(not(feature = "scroll"))]
                assign_exec_step!(self.error_oog_self_destruct)
            }
            ExecutionState::ErrorCodeStore => {
                assign_exec_step!(self.error_code_store)
            }
            ExecutionState::ErrorStack => {
                assign_exec_step!(self.error_stack)
            }
            ExecutionState::ErrorInvalidJump => {
                assign_exec_step!(self.error_invalid_jump)
            }
            ExecutionState::ErrorInvalidOpcode => {
                assign_exec_step!(self.error_invalid_opcode)
            }
            ExecutionState::ErrorWriteProtection => {
                assign_exec_step!(self.error_write_protection)
            }
            ExecutionState::ErrorInvalidCreationCode => {
                assign_exec_step!(self.error_invalid_creation_code)
            }
            ExecutionState::ErrorReturnDataOutOfBound => {
                assign_exec_step!(self.error_return_data_out_of_bound)
            }
            ExecutionState::ErrorPrecompileFailed => {
                assign_exec_step!(self.error_precompile_failed)
            }

            _ => evm_unimplemented!("unimplemented ExecutionState: {:?}", step.execution_state),
        }

        // Fill in the witness values for stored expressions
        let assigned_stored_expressions = self.assign_stored_expressions(region, offset, step)?;

        // enable with `CHECK_RW_LOOKUP=true`
        if *CHECK_RW_LOOKUP {
            let is_padding_step = matches!(step.execution_state, ExecutionState::EndBlock)
                && step.rw_indices.is_empty();
            if !is_padding_step {
                // expensive function call
                Self::check_rw_lookup(
                    &assigned_stored_expressions,
                    offset,
                    step,
                    call,
                    transaction,
                    block,
                    region.challenges(),
                );
            }
        }
        //}
        Ok(())
    }

    fn assign_stored_expressions(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        step: &ExecStep,
    ) -> Result<Vec<(String, F)>, Error> {
        let mut assigned_stored_expressions = Vec::new();
        for stored_expression in self
            .stored_expressions_map
            .get(&step.execution_state)
            .unwrap_or_else(|| panic!("Execution state unknown: {:?}", step.execution_state))
        {
            let assigned = stored_expression.assign(region, offset)?;
            assigned.map(|v| {
                let name = stored_expression.name.clone();
                assigned_stored_expressions.push((name, v));
            });
        }
        Ok(assigned_stored_expressions)
    }

    fn check_rw_lookup(
        assigned_stored_expressions: &[(String, F)],
        offset: usize,
        step: &ExecStep,
        call: &Call,
        transaction: &Transaction,
        block: &Block<F>,
        challenges: &Challenges<Value<F>>,
    ) {
        let mut evm_randomness = F::zero();
        challenges.evm_word().map(|v| evm_randomness = v);
        let mut lookup_randomness = F::zero();
        challenges.lookup_input().map(|v| lookup_randomness = v);
        if evm_randomness.is_zero_vartime() || lookup_randomness.is_zero_vartime() {
            // challenges not ready
            return;
        }
        let mut assigned_rw_values = Vec::new();
        for (name, v) in assigned_stored_expressions {
            if name.starts_with("rw lookup ")
                && !v.is_zero_vartime()
                && !assigned_rw_values.contains(&(name.clone(), *v))
            {
                assigned_rw_values.push((name.clone(), *v));
            }
        }

        let rlc_assignments: BTreeMap<F, Rw> = step
            .rw_indices
            .iter()
            .map(|rw_idx| block.rws[*rw_idx])
            .fold(BTreeMap::<F, Rw>::new(), |mut set, value| {
                let rlc = value.table_assignment_aux(evm_randomness)
                    .rlc(lookup_randomness);
                set.insert(rlc, value);
                set
            });

        // Check that every rw_lookup assigned from the execution steps in the EVM
        // Circuit is in the set of rw operations generated by the step.
        let mut log_ctx_done = false;
        let mut log_ctx = |assigned_rw_values: &[(String, F)]| {
            if log_ctx_done {
                return;
            }
            log_ctx_done = true;
            log::error!("assigned_rw_values {:?}", assigned_rw_values);
            for (idx, rw_idx) in step.rw_indices.iter().enumerate() {
                log::error!(
                    "{}th rw of step: {:?} rlc {:?}",
                    idx,
                    block.rws[*rw_idx],
                    block.rws[*rw_idx]
                        .table_assignment_aux(evm_randomness)
                        .rlc(lookup_randomness)
                );
            }
            let mut tx = transaction.clone();
            tx.call_data.clear();
            tx.calls.clear();
            tx.steps.clear();
            log::error!(
                "ctx: offset {} step {:?}. call: {:?}, tx: {:?}",
                offset,
                step,
                call,
                tx
            );
        };
        for (idx, assigned_rw_value) in assigned_rw_values.iter().enumerate() {
            let (_name, value) = assigned_rw_value;
            if idx >= step.rw_indices.len() {
                log_ctx(&assigned_rw_values);
                panic!(
                    "invalid rw len exp {} witness {}",
                    assigned_rw_values.len(),
                    step.rw_indices.len()
                );
            }
            // Check that the number of rw operations generated from the bus-mapping
            // correspond to the number of assigned rw lookups by the EVM Circuit
            // plus the number of rw lookups done by the copy circuit.
            // if step.rw_indices.len()
            //     != assigned_rw_values.len() + step.copy_rw_counter_delta as usize
            // {
            //     log::error!(
            //     "step.rw_indices.len: {} != assigned_rw_values.len: {} + step.copy_rw_counter_delta: {} in step: {:?}",
            //     step.rw_indices.len(),
            //     assigned_rw_values.len(),
            //     step.copy_rw_counter_delta,
            //     step
            //     );
            // }
            let mut rev_count = 0;
            let is_rev = if assigned_rw_value.0.contains(" with reversion") {
                rev_count += 1;
                true
            } else {
                false
            };
            assert!(
                rev_count <= step.reversible_write_counter_delta,
                "Assigned {} reversions, but step only has {}",
                rev_count,
                step.reversible_write_counter_delta
            );
            // In the EVM Circuit, reversion rw lookups are assigned after their
            // corresponding rw lookup, but in the bus-mapping they are
            // generated at the end of the step.
            let idx = if is_rev {
                step.rw_indices.len() - rev_count
            } else {
                idx - rev_count
            };
            let rw_idx = step.rw_indices[idx];
            let rw = block.rws[rw_idx];
            let table_assignments = rw.table_assignment_aux(evm_randomness);
            let rlc = table_assignments.rlc(lookup_randomness);

            if !rlc_assignments.contains_key(value) {
                log_ctx(&assigned_rw_values);
                log::error!(
                    "incorrect rw witness. input_value {:?}, name \"{}\". table_value {:?}, table_assignments {:?}, rw {:?}, index {:?}, {}th rw of step",
                    assigned_rw_values[idx].1,
                    assigned_rw_values[idx].0,
                    rlc,
                    table_assignments,
                    rw,
                    rw_idx, idx);

                debug_assert_eq!(
                   rlc, assigned_rw_values[idx].1,
                   "left is witness, right is expression"
                );
            }
        }
        // for (idx, assigned_rw_value) in assigned_rw_values.iter().enumerate()
        // {     let rw_idx = step.rw_indices[idx];
        //     let rw = block.rws[rw_idx];
        //     let table_assignments =
        // rw.table_assignment_aux(block.randomness);     let rlc =
        // table_assignments.rlc(block.randomness);     if rlc !=
        // assigned_rw_value.1 {         log::error!(
        //             "incorrect rw witness. lookup input name:
        // \"{}\"\n{:?}\nrw: {:?}, rw index: {:?}, {}th rw of step {:?}",
        //             assigned_rw_value.0,
        //             assigned_rw_value.1,
        //             rw,
        //             rw_idx,
        //             idx,
        //             step.execution_state);
        //     }
        // }
    }
}
