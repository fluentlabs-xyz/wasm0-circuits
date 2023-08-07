use std::cell::RefCell;
use std::marker::PhantomData;
use std::rc::Rc;

use halo2_proofs::{
    plonk::{Column, ConstraintSystem},
};
use halo2_proofs::circuit::{Chip, Region, Value};
use halo2_proofs::plonk::{Advice, Fixed};
use halo2_proofs::poly::Rotation;
use itertools::Itertools;
use log::debug;

use eth_types::Field;
use gadgets::binary_number::BinaryNumberChip;
use gadgets::less_than::{LtChip, LtInstruction};
use gadgets::util::{and, Expr, not, or};

use crate::evm_circuit::util::constraint_builder::{BaseConstraintBuilder, ConstrainBuilderCommon};
use crate::wasm_circuit::bytecode::bytecode::WasmBytecode;
use crate::wasm_circuit::bytecode::bytecode_table::WasmBytecodeTable;
use crate::wasm_circuit::common::{WasmAssignAwareChip, WasmBlockLevelAwareChip, WasmCountPrefixedItemsAwareChip, WasmFuncCountAwareChip, WasmLenPrefixedBytesSpanAwareChip, WasmMarkupLeb128SectionAwareChip, WasmSharedStateAwareChip};
use crate::wasm_circuit::common::{configure_constraints_for_q_first_and_q_last, configure_transition_check};
use crate::wasm_circuit::consts::{CONTROL_INSTRUCTION_BLOCK, CONTROL_INSTRUCTION_WITH_LEB_ARG, CONTROL_INSTRUCTION_WITHOUT_ARGS, ControlInstruction, NUMERIC_INSTRUCTION_WITH_LEB_ARG, NUMERIC_INSTRUCTIONS_WITHOUT_ARGS, NumericInstruction, PARAMETRIC_INSTRUCTIONS_WITHOUT_ARGS, ParametricInstruction, VARIABLE_INSTRUCTION_WITH_LEB_ARG, VariableInstruction, WASM_BLOCK_END, WASM_BLOCKTYPE_DELIMITER};
use crate::wasm_circuit::error::Error;
use crate::wasm_circuit::leb128_circuit::circuit::LEB128Chip;
use crate::wasm_circuit::sections::code::code_body::types::AssignType;
use crate::wasm_circuit::sections::consts::LebParams;
use crate::wasm_circuit::tables::dynamic_indexes::circuit::DynamicIndexesChip;
use crate::wasm_circuit::types::SharedState;

#[derive(Debug, Clone)]
pub struct WasmCodeSectionBodyConfig<F: Field> {
    pub q_enable: Column<Fixed>,
    pub q_first: Column<Fixed>,
    pub q_last: Column<Fixed>,
    pub is_funcs_count: Column<Fixed>,
    pub is_func_body_len: Column<Fixed>,
    pub is_local_type_transitions_count: Column<Fixed>,
    pub is_local_repetition_count: Column<Fixed>,
    pub is_local_type: Column<Fixed>,

    pub is_numeric_instruction: Column<Fixed>,
    pub is_numeric_instruction_leb_arg: Column<Fixed>,
    pub is_variable_instruction: Column<Fixed>,
    pub is_variable_instruction_leb_arg: Column<Fixed>,
    pub is_control_instruction: Column<Fixed>,
    pub is_control_instruction_leb_arg: Column<Fixed>,
    pub is_parametric_instruction: Column<Fixed>,
    pub is_blocktype_delimiter: Column<Fixed>,
    pub is_block_end: Column<Fixed>,

    pub leb128_chip: Rc<LEB128Chip<F>>,
    pub numeric_instructions_chip: Rc<BinaryNumberChip<F, NumericInstruction, 8>>,
    pub variable_instruction_chip: Rc<BinaryNumberChip<F, VariableInstruction, 8>>,
    pub control_instruction_chip: Rc<BinaryNumberChip<F, ControlInstruction, 8>>,
    pub parametric_instruction_chip: Rc<BinaryNumberChip<F, ParametricInstruction, 8>>,
    pub dynamic_indexes_chip: Rc<DynamicIndexesChip<F>>,

    pub func_count: Column<Advice>,
    pub block_level: Column<Advice>,
    pub block_level_lt_chip: Rc<LtChip<F, 2>>,
    body_byte_rev_index: Column<Advice>,
    body_item_rev_count: Column<Advice>,

    pub shared_state: Rc<RefCell<SharedState>>,

    _marker: PhantomData<F>,
}

impl<'a, F: Field> WasmCodeSectionBodyConfig<F> {}

#[derive(Debug, Clone)]
pub struct WasmCodeSectionBodyChip<F: Field> {
    pub config: WasmCodeSectionBodyConfig<F>,
    _marker: PhantomData<F>,
}

impl<F: Field> WasmAssignAwareChip<F> for WasmCodeSectionBodyChip<F> {
    type AssignType = AssignType;

    fn assign(
        &self,
        region: &mut Region<F>,
        wasm_bytecode: &WasmBytecode,
        offset: usize,
        assign_types: &[Self::AssignType],
        assign_value: u64,
        leb_params: Option<LebParams>,
    ) {
        let q_enable = true;
        debug!(
            "assign at offset {} q_enable {} assign_types {:?} assign_value {} byte_val {:x?}",
            offset,
            q_enable,
            assign_types,
            assign_value,
            wasm_bytecode.bytes[offset],
        );
        region.assign_fixed(
            || format!("assign 'q_enable' val {} at {}", q_enable, offset),
            self.config.q_enable,
            offset,
            || Value::known(F::from(q_enable as u64)),
        ).unwrap();
        self.assign_func_count(region, offset);
        self.assign_block_level(region, offset);

        assign_types.iter().for_each(|&assign_type| {
            if [
                AssignType::IsFuncsCount,
                AssignType::IsFuncBodyLen,
                AssignType::IsLocalTypeTransitionsCount,
                AssignType::IsLocalRepetitionCount,
                AssignType::IsNumericInstructionLebArg,
                AssignType::IsVariableInstructionLebArg,
                AssignType::IsControlInstructionLebArg
            ].contains(&assign_type) {
                let p = leb_params.unwrap();
                self.config.leb128_chip.assign(
                    region,
                    offset,
                    q_enable,
                    p,
                );
            }
            match assign_type {
                AssignType::QFirst => {
                    region.assign_fixed(
                        || format!("assign 'q_first' val {} at {}", assign_value, offset),
                        self.config.q_first,
                        offset,
                        || Value::known(F::from(assign_value)),
                    ).unwrap();
                }
                AssignType::QLast => {
                    region.assign_fixed(
                        || format!("assign 'q_last' val {} at {}", assign_value, offset),
                        self.config.q_last,
                        offset,
                        || Value::known(F::from(assign_value)),
                    ).unwrap();
                }
                AssignType::Unknown => {
                    panic!("assign type is unknown")
                }
                AssignType::IsFuncsCount => {
                    region.assign_fixed(
                        || format!("assign 'is_funcs_count' val {} at {}", assign_value, offset),
                        self.config.is_funcs_count,
                        offset,
                        || Value::known(F::from(assign_value)),
                    ).unwrap();
                }
                AssignType::IsFuncBodyLen => {
                    region.assign_fixed(
                        || format!("assign 'is_func_body_len' val {} at {}", assign_value, offset),
                        self.config.is_func_body_len,
                        offset,
                        || Value::known(F::from(assign_value)),
                    ).unwrap();
                }
                AssignType::IsLocalTypeTransitionsCount => {
                    region.assign_fixed(
                        || format!("assign 'is_local_type_transitions_count' val {} at {}", assign_value, offset),
                        self.config.is_local_type_transitions_count,
                        offset,
                        || Value::known(F::from(assign_value)),
                    ).unwrap();
                }
                AssignType::IsLocalRepetitionCount => {
                    region.assign_fixed(
                        || format!("assign 'is_local_repetition_count' val {} at {}", assign_value, offset),
                        self.config.is_local_repetition_count,
                        offset,
                        || Value::known(F::from(assign_value)),
                    ).unwrap();
                }
                AssignType::IsLocalType => {
                    region.assign_fixed(
                        || format!("assign 'is_local_type' val {} at {}", assign_value, offset),
                        self.config.is_local_type,
                        offset,
                        || Value::known(F::from(assign_value)),
                    ).unwrap();
                }
                AssignType::IsNumericInstruction => {
                    region.assign_fixed(
                        || format!("assign 'is_numeric_instruction' val {} at {}", assign_value, offset),
                        self.config.is_numeric_instruction,
                        offset,
                        || Value::known(F::from(assign_value)),
                    ).unwrap();
                    if assign_value == 1 {
                        let opcode: NumericInstruction = wasm_bytecode.bytes[offset].try_into().unwrap();
                        self.config.numeric_instructions_chip.assign(
                            region,
                            offset,
                            &opcode,
                        ).unwrap();
                    }
                }
                AssignType::IsNumericInstructionLebArg => {
                    region.assign_fixed(
                        || format!("assign 'is_numeric_instruction_leb_arg' val {} at {}", assign_value, offset),
                        self.config.is_numeric_instruction_leb_arg,
                        offset,
                        || Value::known(F::from(assign_value)),
                    ).unwrap();
                }
                AssignType::IsVariableInstruction => {
                    region.assign_fixed(
                        || format!("assign 'is_variable_instruction' val {} at {}", assign_value, offset),
                        self.config.is_variable_instruction,
                        offset,
                        || Value::known(F::from(assign_value)),
                    ).unwrap();
                    if assign_value == 1 {
                        let opcode = wasm_bytecode.bytes[offset].try_into().unwrap();
                        self.config.variable_instruction_chip.assign(
                            region,
                            offset,
                            &opcode,
                        ).unwrap();
                    }
                }
                AssignType::IsVariableInstructionLebArg => {
                    region.assign_fixed(
                        || format!("assign 'is_variable_instruction_leb_arg' val {} at {}", assign_value, offset),
                        self.config.is_variable_instruction_leb_arg,
                        offset,
                        || Value::known(F::from(assign_value)),
                    ).unwrap();
                }
                AssignType::IsControlInstruction => {
                    region.assign_fixed(
                        || format!("assign 'is_control_instruction' val {} at {}", assign_value, offset),
                        self.config.is_control_instruction,
                        offset,
                        || Value::known(F::from(assign_value)),
                    ).unwrap();
                    if assign_value == 1 {
                        let opcode = wasm_bytecode.bytes[offset].try_into().unwrap();
                        self.config.control_instruction_chip.assign(
                            region,
                            offset,
                            &opcode,
                        ).unwrap();
                    }
                }
                AssignType::IsControlInstructionLebArg => {
                    region.assign_fixed(
                        || format!("assign 'is_control_instruction_leb_arg' val {} at {}", assign_value, offset),
                        self.config.is_control_instruction_leb_arg,
                        offset,
                        || Value::known(F::from(assign_value)),
                    ).unwrap();
                }
                AssignType::IsParametricInstruction => {
                    region.assign_fixed(
                        || format!("assign 'is_parametric_instruction' val {} at {}", assign_value, offset),
                        self.config.is_parametric_instruction,
                        offset,
                        || Value::known(F::from(assign_value)),
                    ).unwrap();
                    if assign_value == 1 {
                        let opcode = wasm_bytecode.bytes[offset].try_into().unwrap();
                        self.config.parametric_instruction_chip.assign(
                            region,
                            offset,
                            &opcode,
                        ).unwrap();
                    }
                }
                AssignType::IsBlocktypeDelimiter => {
                    region.assign_fixed(
                        || format!("assign 'is_blocktype_delimiter' val {} at {}", assign_value, offset),
                        self.config.is_blocktype_delimiter,
                        offset,
                        || Value::known(F::from(assign_value)),
                    ).unwrap();
                }
                AssignType::IsBlockEnd => {
                    region.assign_fixed(
                        || format!("assign 'is_block_end' val {} at {}", assign_value, offset),
                        self.config.is_block_end,
                        offset,
                        || Value::known(F::from(assign_value)),
                    ).unwrap();
                }
                AssignType::BodyByteRevIndex => {
                    region.assign_advice(
                        || format!("assign 'body_byte_rev_index' val {} at {}", assign_value, offset),
                        self.config.body_byte_rev_index,
                        offset,
                        || Value::known(F::from(assign_value)),
                    ).unwrap();
                }
                AssignType::BodyItemRevCount => {
                    region.assign_advice(
                        || format!("assign 'body_item_rev_count' val {} at {}", assign_value, offset),
                        self.config.body_item_rev_count,
                        offset,
                        || Value::known(F::from(assign_value)),
                    ).unwrap();
                }
            }
        })
    }
}

impl<F: Field> WasmMarkupLeb128SectionAwareChip<F> for WasmCodeSectionBodyChip<F> {}

impl<F: Field> WasmLenPrefixedBytesSpanAwareChip<F> for WasmCodeSectionBodyChip<F> {}

impl<F: Field> WasmCountPrefixedItemsAwareChip<F> for WasmCodeSectionBodyChip<F> {}

impl<F: Field> WasmSharedStateAwareChip<F> for WasmCodeSectionBodyChip<F> {
    fn shared_state(&self) -> Rc<RefCell<SharedState>> {
        self.config.shared_state.clone()
    }
}

impl<F: Field> WasmFuncCountAwareChip<F> for WasmCodeSectionBodyChip<F> {
    fn func_count_col(&self) -> Column<Advice> { self.config.func_count }
}

impl<F: Field> WasmBlockLevelAwareChip<F> for WasmCodeSectionBodyChip<F> {
    fn block_level_col(&self) -> Column<Advice> { self.config.block_level }
}

impl<F: Field> WasmCodeSectionBodyChip<F>
{
    pub fn construct(config: WasmCodeSectionBodyConfig<F>) -> Self {
        let instance = Self {
            config,
            _marker: PhantomData,
        };
        instance
    }

    pub fn configure(
        cs: &mut ConstraintSystem<F>,
        bytecode_table: Rc<WasmBytecodeTable>,
        leb128_chip: Rc<LEB128Chip<F>>,
        dynamic_indexes_chip: Rc<DynamicIndexesChip<F>>,
        func_count: Column<Advice>,
        shared_state: Rc<RefCell<SharedState>>,
        body_byte_rev_index: Column<Advice>,
        body_item_rev_count: Column<Advice>,
    ) -> WasmCodeSectionBodyConfig<F> {
        let q_enable = cs.fixed_column();
        let q_first = cs.fixed_column();
        let q_last = cs.fixed_column();
        let is_funcs_count = cs.fixed_column();
        let is_func_body_len = cs.fixed_column();
        let is_local_type_transitions_count = cs.fixed_column();
        let is_local_repetition_count = cs.fixed_column();
        let is_local_type = cs.fixed_column();

        let block_level = cs.advice_column();

        let is_numeric_instruction = cs.fixed_column();
        let is_numeric_instruction_leb_arg = cs.fixed_column();
        let is_variable_instruction = cs.fixed_column();
        let is_variable_instruction_leb_arg = cs.fixed_column();
        let is_control_instruction = cs.fixed_column();
        let is_control_instruction_leb_arg = cs.fixed_column();
        let is_parametric_instruction = cs.fixed_column();
        let is_blocktype_delimiter = cs.fixed_column();
        let is_block_end = cs.fixed_column();

        let config = BinaryNumberChip::configure(
            cs,
            is_numeric_instruction,
            Some(bytecode_table.value.into()),
        );
        let numeric_instructions_chip = Rc::new(BinaryNumberChip::construct(config));

        let config = BinaryNumberChip::configure(
            cs,
            is_control_instruction,
            Some(bytecode_table.value.into()),
        );
        let control_instruction_chip = Rc::new(BinaryNumberChip::construct(config));

        let config = BinaryNumberChip::configure(
            cs,
            is_parametric_instruction,
            Some(bytecode_table.value.into()),
        );
        let parametric_instruction_chip = Rc::new(BinaryNumberChip::construct(config));

        let config = BinaryNumberChip::configure(
            cs,
            is_variable_instruction,
            Some(bytecode_table.value.into()),
        );
        let variable_instruction_chip = Rc::new(BinaryNumberChip::construct(config));

        let config = LtChip::configure(
            cs,
            |vc| {
                let q_enable_expr = vc.query_fixed(q_enable, Rotation::cur());
                let q_first_expr = vc.query_fixed(q_first, Rotation::cur());
                let not_q_first_expr = not::expr(q_first_expr.clone());
                let is_br_prev_expr = control_instruction_chip.config.value_equals(ControlInstruction::Br, Rotation::prev())(vc);
                let is_br_if_prev_expr = control_instruction_chip.config.value_equals(ControlInstruction::BrIf, Rotation::prev())(vc);

                and::expr([
                    q_enable_expr.clone(),
                    not_q_first_expr,
                    or::expr([
                        is_br_prev_expr,
                        is_br_if_prev_expr,
                    ])
                ])
            },
            |vc| {
                vc.query_advice(leb128_chip.config.sn, Rotation::cur())
            },
            |vc| {
                vc.query_advice(block_level, Rotation::cur())
            },
        );
        let block_level_lt_chip = Rc::new(LtChip::construct(config));

        Self::configure_len_prefixed_bytes_span_checks(
            cs,
            leb128_chip.as_ref(),
            |vc| {
                or::expr([
                    is_local_type_transitions_count,
                    is_local_repetition_count,
                    is_local_type,
                    is_numeric_instruction,
                    is_numeric_instruction_leb_arg,
                    is_variable_instruction,
                    is_variable_instruction_leb_arg,
                    is_control_instruction,
                    is_control_instruction_leb_arg,
                    is_parametric_instruction,
                    is_blocktype_delimiter,
                    is_block_end,
                ].map(|c| vc.query_fixed(c, Rotation::cur())).iter().collect_vec())
            },
            body_byte_rev_index,
            |vc| {
                let not_q_last_expr = not::expr(vc.query_fixed(q_last, Rotation::cur()));
                let is_func_body_len_expr = vc.query_fixed(is_func_body_len, Rotation::cur());
                let is_local_type_transitions_count_next_expr = vc.query_fixed(is_local_type_transitions_count, Rotation::next());

                and::expr([not_q_last_expr, is_func_body_len_expr, is_local_type_transitions_count_next_expr])
            },
            |vc| {
                let q_last_expr = vc.query_fixed(q_last, Rotation::cur());
                let is_block_end_expr = vc.query_fixed(is_block_end, Rotation::cur());
                let is_func_body_len_next_expr = vc.query_fixed(is_func_body_len, Rotation::next());

                or::expr([
                    q_last_expr,
                    and::expr([
                        is_block_end_expr,
                        is_func_body_len_next_expr,
                    ])
                ])
            },
        );

        Self::configure_count_prefixed_items_checks(
            cs,
            leb128_chip.as_ref(),
            body_item_rev_count,
            |vc| vc.query_fixed(is_funcs_count, Rotation::cur()),
            |vc| {
                let q_enable_expr = vc.query_fixed(q_enable, Rotation::cur());
                let is_funcs_count_expr = vc.query_fixed(is_funcs_count, Rotation::cur());

                and::expr([
                    q_enable_expr,
                    not::expr(is_funcs_count_expr),
                ])
            },
            |vc| {
                let q_first_expr = vc.query_fixed(q_first, Rotation::cur());
                let is_block_end_prev_expr = vc.query_fixed(is_block_end, Rotation::prev());
                let is_func_body_len_expr = vc.query_fixed(is_func_body_len, Rotation::cur());
                let is_funcs_count_prev_expr = vc.query_fixed(is_funcs_count, Rotation::prev());


                and::expr([
                    not::expr(q_first_expr),
                    is_func_body_len_expr,
                    or::expr([is_funcs_count_prev_expr, is_block_end_prev_expr]),
                ])
            },
            |vc| {
                let q_last_expr = vc.query_fixed(q_last, Rotation::cur());
                let is_block_end_expr = vc.query_fixed(is_block_end, Rotation::cur());
                let is_func_body_len_next_expr = vc.query_fixed(is_func_body_len, Rotation::cur());

                and::expr([
                    not::expr(q_last_expr),
                    is_block_end_expr,
                    is_func_body_len_next_expr,
                ])
            },
        );

        cs.create_gate("WasmCodeSectionBody gate", |vc| {
            let mut cb = BaseConstraintBuilder::default();

            let q_enable_expr = vc.query_fixed(q_enable, Rotation::cur());
            let q_first_expr = vc.query_fixed(q_first, Rotation::cur());
            let q_last_expr = vc.query_fixed(q_last, Rotation::cur());
            let not_q_last_expr = not::expr(q_last_expr.clone());
            let is_funcs_count_prev_expr = vc.query_fixed(is_funcs_count, Rotation::prev());
            let is_funcs_count_expr = vc.query_fixed(is_funcs_count, Rotation::cur());
            let is_func_body_len_expr = vc.query_fixed(is_func_body_len, Rotation::cur());
            let is_local_type_transitions_count_expr = vc.query_fixed(is_local_type_transitions_count, Rotation::cur());
            let is_local_repetition_count_expr = vc.query_fixed(is_local_repetition_count, Rotation::cur());
            let is_local_type_expr = vc.query_fixed(is_local_type, Rotation::cur());
            let is_numeric_instruction_expr = vc.query_fixed(is_numeric_instruction, Rotation::cur());
            let is_numeric_instruction_leb_arg_expr = vc.query_fixed(is_numeric_instruction_leb_arg, Rotation::cur());
            let is_variable_instruction_expr = vc.query_fixed(is_variable_instruction, Rotation::cur());
            let is_variable_instruction_leb_arg_expr = vc.query_fixed(is_variable_instruction_leb_arg, Rotation::cur());
            let is_control_instruction_expr = vc.query_fixed(is_control_instruction, Rotation::cur());
            let is_control_instruction_leb_arg_expr = vc.query_fixed(is_control_instruction_leb_arg, Rotation::cur());
            let is_parametric_instruction_expr = vc.query_fixed(is_parametric_instruction, Rotation::cur());
            let is_blocktype_delimiter_expr = vc.query_fixed(is_blocktype_delimiter, Rotation::cur());
            let is_block_end_prev_expr = vc.query_fixed(is_block_end, Rotation::prev());
            let is_block_end_expr = vc.query_fixed(is_block_end, Rotation::cur());

            let leb128_chip_q_enable_expr = vc.query_fixed(leb128_chip.config.q_enable, Rotation::cur());
            let leb128_chip_q_enable_next_expr = vc.query_fixed(leb128_chip.config.q_enable, Rotation::next());

            let byte_val_expr = vc.query_advice(bytecode_table.value, Rotation::cur());
            let block_level_expr = vc.query_advice(block_level, Rotation::cur());

            cb.require_boolean("q_enable is boolean", q_enable_expr.clone());
            cb.require_boolean("is_funcs_count is boolean", is_funcs_count_expr.clone());
            cb.require_boolean("is_func_body_len is boolean", is_func_body_len_expr.clone());
            cb.require_boolean("is_local_type_transitions_count is boolean", is_local_type_transitions_count_expr.clone());
            cb.require_boolean("is_local_repetition_count is boolean", is_local_repetition_count_expr.clone());
            cb.require_boolean("is_local_type is boolean", is_local_type_expr.clone());
            cb.require_boolean("is_numeric_instruction is boolean", is_numeric_instruction_expr.clone());
            cb.require_boolean("is_numeric_instruction_leb_arg is boolean", is_numeric_instruction_leb_arg_expr.clone());
            cb.require_boolean("is_variable_instruction is boolean", is_variable_instruction_expr.clone());
            cb.require_boolean("is_variable_instruction_leb_arg is boolean", is_variable_instruction_leb_arg_expr.clone());
            cb.require_boolean("is_control_instruction is boolean", is_control_instruction_expr.clone());
            cb.require_boolean("is_control_instruction_leb_arg is boolean", is_control_instruction_leb_arg_expr.clone());
            cb.require_boolean("is_parametric_instruction is boolean", is_parametric_instruction_expr.clone());

            configure_constraints_for_q_first_and_q_last(
                &mut cb,
                vc,
                &q_enable,
                &q_first,
                &[is_funcs_count],
                &q_last,
                &[
                    is_block_end,
                ],
            );

            let is_numeric_opcode_without_params_expr = or::expr(
                NUMERIC_INSTRUCTIONS_WITHOUT_ARGS.iter()
                    .map(|v| {
                        numeric_instructions_chip.config.value_equals(*v, Rotation::cur())(vc)
                    }).collect_vec()
            );
            let is_numeric_opcode_with_leb_param_expr = or::expr(
                NUMERIC_INSTRUCTION_WITH_LEB_ARG.iter()
                    .map(|v| {
                        numeric_instructions_chip.config.value_equals(*v, Rotation::cur())(vc)
                    }).collect_vec()
            );
            let is_variable_opcode_with_leb_param_expr = or::expr(
                VARIABLE_INSTRUCTION_WITH_LEB_ARG.iter()
                    .map(|v| {
                        variable_instruction_chip.config.value_equals(*v, Rotation::cur())(vc)
                    }).collect_vec()
            );
            let is_control_opcode_without_params_expr = or::expr(
                CONTROL_INSTRUCTION_WITHOUT_ARGS.iter()
                    .map(|v| {
                        control_instruction_chip.config.value_equals(*v, Rotation::cur())(vc)
                    }).collect_vec()
            );
            let is_control_opcode_with_leb_param_expr = or::expr(
                CONTROL_INSTRUCTION_WITH_LEB_ARG.iter()
                    .map(|v| {
                        control_instruction_chip.config.value_equals(*v, Rotation::cur())(vc)
                    }).collect_vec()
            );
            let is_control_opcode_block_expr = or::expr(
                CONTROL_INSTRUCTION_BLOCK.iter()
                    .map(|v| {
                        control_instruction_chip.config.value_equals(*v, Rotation::cur())(vc)
                    }).collect_vec()
            );
            let is_parametric_opcode_without_params_expr = or::expr(
                PARAMETRIC_INSTRUCTIONS_WITHOUT_ARGS.iter()
                    .map(|v| {
                        parametric_instruction_chip.config.value_equals(*v, Rotation::cur())(vc)
                    }).collect_vec()
            );

            let is_instruction_expr = or::expr([
                is_numeric_instruction_expr.clone(),
                is_variable_instruction_expr.clone(),
                is_control_instruction_expr.clone(),
                is_parametric_instruction_expr.clone(),
            ]);
            let is_instruction_leb_arg_expr = or::expr([
                is_numeric_instruction_leb_arg_expr.clone(),
                is_variable_instruction_leb_arg_expr.clone(),
                is_control_instruction_leb_arg_expr.clone(),
            ]);

            // block_level constraints
            cb.condition(
                q_first_expr.clone(),
                |bcb| {
                    bcb.require_zero(
                        "q_first => block_level=0",
                        block_level_expr.clone(),
                    );
                }
            );
            cb.condition(
                q_last_expr.clone(),
                |bcb| {
                    bcb.require_zero(
                        "q_last => block_level=0",
                        block_level_expr.clone(),
                    );
                }
            );
            cb.condition(
                and::expr([
                    is_func_body_len_expr.clone(),
                    or::expr([
                        is_funcs_count_prev_expr.clone(),
                        is_block_end_prev_expr.clone(),
                    ]),
                ]),
                |bcb| {
                    bcb.require_zero(
                        "block_level=1 on is_func_body_len transition",
                        block_level_expr.clone() - 1.expr(),
                    );
                }
            );
            cb.condition(
                is_control_opcode_block_expr.clone(),
                |bcb| {
                    let block_level_prev_expr = vc.query_advice(block_level, Rotation::prev());
                    bcb.require_equal(
                        "is_control_opcode_block => prev.block_level+1=block_level",
                        block_level_prev_expr + 1.expr(),
                        block_level_expr.clone(),
                    );
                }
            );
            cb.condition(
                is_block_end_expr.clone(),
                |bcb| {
                    let block_level_prev_expr = vc.query_advice(block_level, Rotation::prev());
                    bcb.require_equal(
                        "is_block_end => prev.block_level-1=block_level",
                        block_level_prev_expr - 1.expr(),
                        block_level_expr.clone(),
                    );
                }
            );
            cb.condition(
                and::expr([
                    not::expr(q_first_expr.clone()),
                    not::expr(q_last_expr.clone()),
                    not::expr(and::expr([
                        is_func_body_len_expr.clone(),
                        or::expr([
                            is_funcs_count_prev_expr.clone(),
                            is_block_end_prev_expr.clone(),
                        ]),
                    ])),
                    not::expr(is_control_opcode_block_expr.clone()),
                    not::expr(is_block_end_expr.clone()),
                ]),
                |bcb| {
                    let block_level_prev_expr = vc.query_advice(block_level, Rotation::prev());
                    bcb.require_zero(
                        "prev.block_level_expr=block_level",
                        block_level_expr.clone() - block_level_prev_expr,
                    );
                }
            );

            cb.require_equal(
                "exactly one mark flag active at the same time",
                is_funcs_count_expr.clone()
                    + is_func_body_len_expr.clone()
                    + is_local_type_transitions_count_expr.clone()
                    + is_local_repetition_count_expr.clone()
                    + is_local_type_expr.clone()
                    + is_numeric_instruction_expr.clone()
                    + is_numeric_instruction_leb_arg_expr.clone()
                    + is_variable_instruction_expr.clone()
                    + is_variable_instruction_leb_arg_expr.clone()
                    + is_control_instruction_expr.clone()
                    + is_control_instruction_leb_arg_expr.clone()
                    + is_parametric_instruction_expr.clone()
                    + is_blocktype_delimiter_expr.clone()
                    + is_block_end_expr.clone(),
                1.expr(),
            );

            // is_funcs_count+ -> func+(is_func_body_len+ -> locals{1}(is_local_type_transitions_count+ -> local_var_descriptor*(is_local_repetition_count+ -> is_local_type{1})) -> is_func_body_code+)
            configure_transition_check(
                &mut cb,
                vc,
                "check next: is_funcs_count+ -> func+(is_func_body_len+ ...",
                is_funcs_count_expr.clone(),
                true,
                &[is_funcs_count, is_func_body_len, ],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: is_func_body_len+ -> locals(1)(is_local_type_transitions_count+ ...",
                is_func_body_len_expr.clone(),
                true,
                &[is_func_body_len, is_local_type_transitions_count, ],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: is_local_type_transitions_count+ -> local_var_descriptor*(is_local_repetition_count+ ...",
                is_local_type_transitions_count_expr.clone(),
                true,
                &[
                    is_local_type_transitions_count, is_local_repetition_count,
                    is_numeric_instruction, is_variable_instruction, is_control_instruction, is_parametric_instruction, is_block_end,
                ],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: is_local_repetition_count+ -> is_local_type(1) ...",
                is_local_repetition_count_expr.clone(),
                true,
                &[is_local_repetition_count, is_local_type, ],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: ... is_local_type(1))) -> is_func_body_code+",
                is_local_type_expr.clone(),
                true,
                &[is_local_repetition_count, is_numeric_instruction, is_variable_instruction, is_control_instruction, is_parametric_instruction, ],
            );

            // BASIC CONSTRAINTS:

            cb.condition(
                is_numeric_instruction_expr.clone(),
                |bcb| {
                    bcb.require_equal(
                        "is_numeric_instruction(1) -> opcode is valid",
                        or::expr([
                            is_numeric_opcode_without_params_expr.clone(),
                            is_numeric_opcode_with_leb_param_expr.clone(),
                        ]),
                        1.expr(),
                    );
                }
            );

            cb.condition(
                is_variable_instruction_expr.clone(),
                |bcb| {
                    bcb.require_equal(
                        "is_variable_instruction(1) => opcode is valid",
                        or::expr(
                            VARIABLE_INSTRUCTION_WITH_LEB_ARG.iter()
                                .map(|v| {
                                    variable_instruction_chip.config.value_equals(*v, Rotation::cur())(vc)
                                }).collect_vec()
                        ),
                        1.expr(),
                    );
                }
            );

            cb.condition(
                is_control_instruction_expr.clone(),
                |bcb| {
                    bcb.require_equal(
                        "is_control_instruction(1) -> opcode is valid",
                        or::expr([
                            is_control_opcode_without_params_expr.clone(),
                            is_control_opcode_with_leb_param_expr.clone(),
                            is_control_opcode_block_expr.clone(),
                        ]),
                        1.expr(),
                    );
                }
            );

            cb.condition(
                is_parametric_instruction_expr.clone(),
                |bcb| {
                    bcb.require_equal(
                        "is_parametric_instruction(1) -> opcode is valid",
                        or::expr([
                            is_parametric_opcode_without_params_expr.clone(),
                        ]),
                        1.expr(),
                    );
                }
            );

            cb.condition(
                or::expr([
                    is_funcs_count_expr.clone(),
                    is_func_body_len_expr.clone(),
                    is_local_type_transitions_count_expr.clone(),
                    is_local_repetition_count_expr.clone(),
                    is_instruction_leb_arg_expr.clone(),
                ]),
                |bcb| {
                    bcb.require_equal(
                        "leb128 flag is active => leb128_chip enabled",
                        leb128_chip_q_enable_expr.clone(),
                        1.expr(),
                    )
                }
            );
            // is_blocktype_delimiter{1} => WASM_BLOCKTYPE_DELIMITER
            cb.condition(
                is_blocktype_delimiter_expr.clone(),
                |bcb| {
                    bcb.require_equal(
                        "is_blocktype_delimiter(1) => WASM_BLOCKTYPE_DELIMITER",
                        byte_val_expr.clone(),
                        WASM_BLOCKTYPE_DELIMITER.expr(),
                    );
                }
            );
            // is_block_end{1} => WASM_BLOCK_END
            cb.condition(
                is_block_end_expr.clone(),
                |bcb| {
                    bcb.require_equal(
                        "is_block_end(1) => WASM_BLOCK_END",
                        byte_val_expr.clone(),
                        WASM_BLOCK_END.expr(),
                    );
                }
            );

            // SIMPLE RELATIONS CONSTRAINTS:

            // is_numeric_opcode_with_leb_param{1} -> is_numeric_instruction_leb_arg+
            cb.condition(
                is_numeric_opcode_with_leb_param_expr.clone(),
                |bcb| {
                    bcb.require_equal(
                        "is_numeric_opcode_with_leb_param(1) -> is_leb128",
                        leb128_chip_q_enable_next_expr.clone(),
                        1.expr(),
                    );
                }
            );

            // is_variable_opcode_with_leb_param{1} -> is_variable_instruction_leb_arg+
            cb.condition(
                is_variable_opcode_with_leb_param_expr.clone(),
                |bcb| {
                    let is_variable_instruction_leb_arg_next_expr = vc.query_fixed(is_variable_instruction_leb_arg, Rotation::next());
                    bcb.require_equal(
                        "is_variable_opcode_with_leb_param(1) -> is_variable_instruction_leb_arg+",
                        is_variable_instruction_leb_arg_next_expr.clone(),
                        1.expr(),
                    );
                }
            );

            // is_control_opcode_with_leb_param{1} -> is_control_instruction_leb_arg+
            cb.condition(
                is_control_opcode_with_leb_param_expr.clone(),
                |bcb| {
                    let is_control_instruction_leb_arg_next_expr = vc.query_fixed(is_control_instruction_leb_arg, Rotation::next());
                    bcb.require_equal(
                        "is_control_opcode_with_leb_param(1) -> is_control_instruction_leb_arg+",
                        is_control_instruction_leb_arg_next_expr.clone(),
                        1.expr(),
                    );
                }
            );
            // is_control_opcode_block{1} -> is_blocktype_delimiter{1}
            configure_transition_check(
                &mut cb,
                vc,
                "is_control_opcode_block(1) -> is_blocktype_delimiter(1)",
                and::expr([
                    is_control_opcode_block_expr.clone(),
                ]),
                true,
                &[is_blocktype_delimiter],
            );

            // COMPLEX RELATIONS CONSTRAINTS:

            // is_numeric_instruction{1} -> is_instruction_leb_arg || is_instruction || is_block_end
            cb.condition(
                is_numeric_instruction_expr.clone(),
                |bcb| {
                    let is_numeric_instruction_leb_arg_next_expr = vc.query_fixed(is_numeric_instruction_leb_arg, Rotation::next());

                    let is_numeric_instruction_next_expr = vc.query_fixed(is_numeric_instruction, Rotation::next());
                    let is_variable_instruction_next_expr = vc.query_fixed(is_variable_instruction, Rotation::next());
                    let is_control_instruction_next_expr = vc.query_fixed(is_control_instruction, Rotation::next());
                    let is_parametric_instruction_next_expr = vc.query_fixed(is_parametric_instruction, Rotation::next());

                    let is_block_end_next_expr = vc.query_fixed(is_block_end, Rotation::next());

                    bcb.require_equal(
                        "check next: is_numeric_instruction(1) -> is_instruction_leb_arg || is_instruction || is_block_end",
                        is_numeric_instruction_leb_arg_next_expr

                            + is_numeric_instruction_next_expr
                            + is_variable_instruction_next_expr
                            + is_control_instruction_next_expr
                            + is_parametric_instruction_next_expr

                            + is_block_end_next_expr
                        ,
                        1.expr(),
                    );
                }
            );

            // is_variable_instruction{1} -> is_instruction_leb_arg || is_instruction || is_block_end
            cb.condition(
                is_variable_instruction_expr.clone(),
                |bcb| {
                    let is_variable_instruction_leb_arg_next_expr = vc.query_fixed(is_variable_instruction_leb_arg, Rotation::next());

                    let is_numeric_instruction_next_expr = vc.query_fixed(is_numeric_instruction, Rotation::next());
                    let is_variable_instruction_next_expr = vc.query_fixed(is_variable_instruction, Rotation::next());
                    let is_control_instruction_next_expr = vc.query_fixed(is_control_instruction, Rotation::next());
                    let is_parametric_instruction_next_expr = vc.query_fixed(is_parametric_instruction, Rotation::next());

                    let is_block_end_next_expr = vc.query_fixed(is_block_end, Rotation::next());

                    bcb.require_equal(
                        "check next: is_variable_instruction(1) -> is_instruction_leb_arg || is_instruction || is_block_end",
                        is_variable_instruction_leb_arg_next_expr

                            + is_numeric_instruction_next_expr
                            + is_variable_instruction_next_expr
                            + is_control_instruction_next_expr
                            + is_parametric_instruction_next_expr

                            + is_block_end_next_expr
                        ,
                        1.expr(),
                    );
                }
            );

            // is_control_instruction{1} && not(is_control_opcode_block) -> is_instruction_leb_arg || is_instruction || is_block_end
            cb.condition(
                and::expr([
                    is_control_instruction_expr.clone(),
                    not::expr(is_control_opcode_block_expr.clone()),
                ]),
                |bcb| {
                    let is_control_instruction_leb_arg_next_expr = vc.query_fixed(is_control_instruction_leb_arg, Rotation::next());

                    let is_numeric_instruction_next_expr = vc.query_fixed(is_numeric_instruction, Rotation::next());
                    let is_variable_instruction_next_expr = vc.query_fixed(is_variable_instruction, Rotation::next());
                    let is_control_instruction_next_expr = vc.query_fixed(is_control_instruction, Rotation::next());
                    let is_parametric_instruction_next_expr = vc.query_fixed(is_parametric_instruction, Rotation::next());

                    let is_block_end_next_expr = vc.query_fixed(is_block_end, Rotation::next());

                    bcb.require_equal(
                        "check next: is_control_instruction(1) && not(is_control_opcode_block) -> is_instruction_leb_arg || is_instruction || is_block_end",
                        is_control_instruction_leb_arg_next_expr

                            + is_numeric_instruction_next_expr
                            + is_variable_instruction_next_expr
                            + is_control_instruction_next_expr
                            + is_parametric_instruction_next_expr

                            + is_block_end_next_expr
                        ,
                        1.expr(),
                    );
                }
            );

            // is_numeric_instruction_leb_arg -> is_instruction || is_block_end
            cb.condition(
                and::expr([
                    is_numeric_instruction_leb_arg_expr.clone(),
                ]),
                |bcb| {
                    let is_numeric_instruction_leb_arg_next_expr = vc.query_fixed(is_numeric_instruction_leb_arg, Rotation::next());
                    let is_variable_instruction_leb_arg_next_expr = vc.query_fixed(is_variable_instruction_leb_arg, Rotation::next());
                    let is_control_instruction_leb_arg_next_expr = vc.query_fixed(is_control_instruction_leb_arg, Rotation::next());

                    let is_numeric_instruction_next_expr = vc.query_fixed(is_numeric_instruction, Rotation::next());
                    let is_variable_instruction_next_expr = vc.query_fixed(is_variable_instruction, Rotation::next());
                    let is_control_instruction_next_expr = vc.query_fixed(is_control_instruction, Rotation::next());
                    let is_parametric_instruction_next_expr = vc.query_fixed(is_parametric_instruction, Rotation::next());

                    let is_instruction_next_expr = is_numeric_instruction_next_expr
                        + is_variable_instruction_next_expr
                        + is_control_instruction_next_expr
                        + is_parametric_instruction_next_expr;

                    let is_block_end_next_expr = vc.query_fixed(is_block_end, Rotation::next());

                    bcb.require_equal(
                        "check next: is_numeric_instruction_leb_arg -> is_instruction || is_block_end",
                        is_numeric_instruction_leb_arg_next_expr

                            + is_instruction_next_expr

                            + is_block_end_next_expr
                        ,
                        1.expr(),
                    );
                }
            );

            // is_variable_instruction_leb_arg -> is_instruction || is_block_end
            cb.condition(
                and::expr([
                    is_variable_instruction_leb_arg_expr.clone(),
                ]),
                |bcb| {
                    let is_numeric_instruction_leb_arg_next_expr = vc.query_fixed(is_numeric_instruction_leb_arg, Rotation::next());
                    let is_variable_instruction_leb_arg_next_expr = vc.query_fixed(is_variable_instruction_leb_arg, Rotation::next());
                    let is_control_instruction_leb_arg_next_expr = vc.query_fixed(is_control_instruction_leb_arg, Rotation::next());

                    let is_numeric_instruction_next_expr = vc.query_fixed(is_numeric_instruction, Rotation::next());
                    let is_variable_instruction_next_expr = vc.query_fixed(is_variable_instruction, Rotation::next());
                    let is_control_instruction_next_expr = vc.query_fixed(is_control_instruction, Rotation::next());
                    let is_parametric_instruction_next_expr = vc.query_fixed(is_parametric_instruction, Rotation::next());

                    let is_instruction_next_expr = is_numeric_instruction_next_expr
                        + is_variable_instruction_next_expr
                        + is_control_instruction_next_expr
                        + is_parametric_instruction_next_expr;

                    let is_block_end_next_expr = vc.query_fixed(is_block_end, Rotation::next());

                    bcb.require_equal(
                        "check next: is_variable_instruction_leb_arg -> is_instruction || is_block_end",
                        is_variable_instruction_leb_arg_next_expr

                            + is_instruction_next_expr

                            + is_block_end_next_expr
                        ,
                        1.expr(),
                    );
                }
            );

            // is_control_instruction_leb_arg -> is_instruction || is_block_end
            cb.condition(
                and::expr([
                    is_control_instruction_leb_arg_expr.clone(),
                ]),
                |bcb| {
                    let is_numeric_instruction_leb_arg_next_expr = vc.query_fixed(is_numeric_instruction_leb_arg, Rotation::next());
                    let is_variable_instruction_leb_arg_next_expr = vc.query_fixed(is_variable_instruction_leb_arg, Rotation::next());
                    let is_control_instruction_leb_arg_next_expr = vc.query_fixed(is_control_instruction_leb_arg, Rotation::next());

                    let is_numeric_instruction_next_expr = vc.query_fixed(is_numeric_instruction, Rotation::next());
                    let is_variable_instruction_next_expr = vc.query_fixed(is_variable_instruction, Rotation::next());
                    let is_control_instruction_next_expr = vc.query_fixed(is_control_instruction, Rotation::next());
                    let is_parametric_instruction_next_expr = vc.query_fixed(is_parametric_instruction, Rotation::next());

                    let is_instruction_next_expr = is_numeric_instruction_next_expr
                        + is_variable_instruction_next_expr
                        + is_control_instruction_next_expr
                        + is_parametric_instruction_next_expr;

                    let is_block_end_next_expr = vc.query_fixed(is_block_end, Rotation::next());

                    bcb.require_equal(
                        "check next: is_control_instruction_leb_arg -> is_instruction || is_block_end",
                        is_control_instruction_leb_arg_next_expr

                            + is_instruction_next_expr

                            + is_block_end_next_expr
                        ,
                        1.expr(),
                    );
                }
            );

            // is_block_end && !not_q_last -> is_instruction || is_block_end
            cb.condition(
                and::expr([
                    is_block_end_expr.clone(),
                    not_q_last_expr.clone(),
                ]),
                |bcb| {
                    let is_numeric_instruction_leb_arg_next_expr = vc.query_fixed(is_numeric_instruction_leb_arg, Rotation::next());
                    let is_variable_instruction_leb_arg_next_expr = vc.query_fixed(is_variable_instruction_leb_arg, Rotation::next());
                    let is_control_instruction_leb_arg_next_expr = vc.query_fixed(is_control_instruction_leb_arg, Rotation::next());

                    let is_func_body_len_next_expr = vc.query_fixed(is_func_body_len, Rotation::next());

                    let is_numeric_instruction_next_expr = vc.query_fixed(is_numeric_instruction, Rotation::next());
                    let is_variable_instruction_next_expr = vc.query_fixed(is_variable_instruction, Rotation::next());
                    let is_control_instruction_next_expr = vc.query_fixed(is_control_instruction, Rotation::next());
                    let is_parametric_instruction_next_expr = vc.query_fixed(is_parametric_instruction, Rotation::next());

                    let is_instruction_next_expr = is_numeric_instruction_next_expr
                        + is_variable_instruction_next_expr
                        + is_control_instruction_next_expr
                        + is_parametric_instruction_next_expr;

                    let is_block_end_next_expr = vc.query_fixed(is_block_end, Rotation::next());

                    bcb.require_equal(
                        "check next: is_block_end && !not_q_last -> is_instruction || is_block_end",
                        is_func_body_len_next_expr

                            + is_instruction_next_expr

                            + is_block_end_next_expr
                        ,
                        1.expr(),
                    );
                }
            );

            let not_q_first_expr = not::expr(q_first_expr.clone());
            let is_br_prev_expr = control_instruction_chip.config.value_equals(ControlInstruction::Br, Rotation::prev())(vc);
            let is_br_if_prev_expr = control_instruction_chip.config.value_equals(ControlInstruction::BrIf, Rotation::prev())(vc);

            cb.condition(
                and::expr([
                    q_enable_expr.clone(),
                    not_q_first_expr,
                    or::expr([
                        is_br_prev_expr,
                        is_br_if_prev_expr,
                    ])
                ]),
                |bcb| {
                    bcb.require_zero(
                        "br/br_if arg is valid",
                        block_level_lt_chip.config().is_lt(vc, None).expr() - 1.expr(),
                    );
                }
            );

            cb.gate(q_enable_expr.clone())
        });

        let config = WasmCodeSectionBodyConfig::<F> {
            _marker: PhantomData,

            q_enable,
            q_first,
            q_last,
            is_funcs_count,
            is_func_body_len,
            is_local_type_transitions_count,
            is_local_repetition_count,
            is_local_type,
            is_numeric_instruction,
            is_numeric_instruction_leb_arg,
            is_variable_instruction,
            is_variable_instruction_leb_arg,
            is_control_instruction,
            is_control_instruction_leb_arg,
            is_parametric_instruction,
            is_blocktype_delimiter,
            is_block_end,
            leb128_chip,
            numeric_instructions_chip,
            variable_instruction_chip,
            control_instruction_chip,
            parametric_instruction_chip,
            dynamic_indexes_chip,
            func_count,
            block_level,
            block_level_lt_chip,
            body_byte_rev_index,
            body_item_rev_count,
            shared_state,
        };

        config
    }

    /// returns new offset
    fn markup_instruction_section(
        &self,
        region: &mut Region<F>,
        wasm_bytecode: &WasmBytecode,
        offset_start: usize,
    ) -> Result<usize, Error> {
        let mut offset = offset_start;

        let opcode = wasm_bytecode.bytes[offset];

        let mut assign_type = AssignType::Unknown;
        let mut assign_type_argument = AssignType::Unknown;

        if let Ok(opcode) = <u8 as TryInto<NumericInstruction>>::try_into(opcode) {
            assign_type = AssignType::IsNumericInstruction;
            if NUMERIC_INSTRUCTION_WITH_LEB_ARG.contains(&opcode) {
                assign_type_argument = AssignType::IsNumericInstructionLebArg;
            }
        }

        if let Ok(opcode) = <u8 as TryInto<VariableInstruction>>::try_into(opcode) {
            assign_type = AssignType::IsVariableInstruction;
            if VARIABLE_INSTRUCTION_WITH_LEB_ARG.contains(&opcode) {
                assign_type_argument = AssignType::IsVariableInstructionLebArg;
            }
        }

        if let Ok(opcode) = <u8 as TryInto<ControlInstruction>>::try_into(opcode) {
            assign_type = AssignType::IsControlInstruction;
            if CONTROL_INSTRUCTION_BLOCK.contains(&opcode) {
                assign_type_argument = AssignType::IsBlocktypeDelimiter;
                self.shared_state().borrow_mut().block_level += 1;
            }
            if CONTROL_INSTRUCTION_WITH_LEB_ARG.contains(&opcode) {
                assign_type_argument = AssignType::IsControlInstructionLebArg
            }
        }

        if let Ok(_opcode) = <u8 as TryInto<ParametricInstruction>>::try_into(opcode) {
            assign_type = AssignType::IsParametricInstruction;
        }

        if opcode == WASM_BLOCK_END {
            assign_type = AssignType::IsBlockEnd;
            self.shared_state().borrow_mut().block_level -= 1;
        };

        if [
            AssignType::IsNumericInstruction,
            AssignType::IsVariableInstruction,
            AssignType::IsControlInstruction,
            AssignType::IsParametricInstruction,
            AssignType::IsBlockEnd,
        ].contains(&assign_type) {
            self.assign(
                region,
                wasm_bytecode,
                offset,
                &[assign_type],
                1,
                None,
            );
            offset += 1;
        }

        if assign_type_argument == AssignType::IsBlocktypeDelimiter {
            self.assign(
                region,
                wasm_bytecode,
                offset,
                &[assign_type_argument],
                1,
                None,
            );
            offset += 1;
        }

        if [
            AssignType::IsNumericInstructionLebArg,
            AssignType::IsVariableInstructionLebArg,
            AssignType::IsControlInstructionLebArg,
        ].contains(&assign_type_argument) {
            let (instr_arg_val, inst_arg_leb_len) = self.markup_leb_section(
                region,
                wasm_bytecode,
                offset,
                &[assign_type_argument],
            );
            let block_level = self.config.shared_state.borrow().block_level;
            debug!(
                "assign at offset {} block_level_lt_chip instr_arg_val {} block_level {}",
                offset,
                instr_arg_val,
                block_level,
            );
            self.config.block_level_lt_chip.assign(
                region,
                offset,
                F::from(instr_arg_val),
                F::from(block_level as u64),
            ).unwrap();
            offset += inst_arg_leb_len;
        }

        if offset == offset_start {
            panic!("failed to detect opcode {} at offset {}", opcode, offset)
        }

        Ok(offset)
    }

    /// updates `shared_state.dynamic_indexes_offset` to a new offset
    ///
    /// returns new offset
    pub fn assign_auto(
        &self,
        region: &mut Region<F>,
        wasm_bytecode: &WasmBytecode,
        offset_start: usize,
    ) -> Result<usize, Error> {
        let mut offset = offset_start;

        // is_funcs_count+
        let (funcs_count, funcs_count_leb_len) = self.markup_leb_section(
            region,
            wasm_bytecode,
            offset,
            &[AssignType::IsFuncsCount],
        );
        let mut body_item_rev_count = funcs_count;
        let funcs_count_last_byte_offset = offset + funcs_count_leb_len - 1;
        self.assign(
            region,
            &wasm_bytecode,
            funcs_count_last_byte_offset,
            &[AssignType::BodyItemRevCount],
            body_item_rev_count,
            None,
        );
        self.config.shared_state.borrow_mut().func_count += funcs_count as usize;
        self.assign(region, &wasm_bytecode, offset, &[AssignType::QFirst], 1, None);
        offset += funcs_count_leb_len;

        for _func_index in 0..funcs_count {
            body_item_rev_count -= 1;
            // is_func_body_len+
            self.config.shared_state.borrow_mut().block_level += 1;
            let (func_body_len, func_body_len_leb_len) = self.markup_leb_section(
                region,
                wasm_bytecode,
                offset,
                &[AssignType::IsFuncBodyLen],
            );
            let func_body_end_offset = offset + func_body_len_leb_len + (func_body_len as usize) - 1;
            for offset in offset..=func_body_end_offset {
                self.assign(
                    region,
                    &wasm_bytecode,
                    offset,
                    &[AssignType::BodyItemRevCount],
                    body_item_rev_count,
                    None,
                );
            }
            let func_body_len_last_byte_offset = offset + func_body_len_leb_len - 1;
            for offset in func_body_len_last_byte_offset..=func_body_end_offset {
                self.assign(
                    region,
                    &wasm_bytecode,
                    offset,
                    &[AssignType::BodyByteRevIndex],
                    (func_body_end_offset - offset) as u64,
                    None,
                );
            }
            offset += func_body_len_leb_len;

            //  locals{1}(is_local_type_transitions_count+ ...
            let (is_local_type_transitions_count, is_local_type_transitions_count_leb_len) = self.markup_leb_section(
                region,
                wasm_bytecode,
                offset,
                &[AssignType::IsLocalTypeTransitionsCount],
            );
            offset += is_local_type_transitions_count_leb_len;

            for _is_valtype_transition_index in 0..is_local_type_transitions_count {
                // -> local_var_descriptor+(is_local_repetition_count+ ...
                let (_is_local_repetition_count, is_local_repetition_count_leb_len) = self.markup_leb_section(
                    region,
                    wasm_bytecode,
                    offset,
                    &[AssignType::IsLocalRepetitionCount],
                );
                offset += is_local_repetition_count_leb_len;

                // is_local_type{1}
                self.assign(
                    region,
                    wasm_bytecode,
                    offset,
                    &[AssignType::IsLocalType],
                    1,
                    None,
                );
                offset += 1;
            }

            while offset <= func_body_end_offset {
                let new_offset = self.markup_instruction_section(
                    region,
                    wasm_bytecode,
                    offset,
                ).unwrap();

                offset = new_offset;
            }
        }

        if offset != offset_start {
            self.assign(region, &wasm_bytecode, offset - 1, &[AssignType::QLast], 1, None);
        }

        Ok(offset)
    }
}