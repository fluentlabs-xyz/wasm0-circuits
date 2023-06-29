use halo2_proofs::{
    plonk::{Column, ConstraintSystem},
};
use std::{marker::PhantomData};
use std::rc::Rc;
use ethers_core::k256::pkcs8::der::Encode;
use halo2_proofs::circuit::{Region, Value};
use halo2_proofs::plonk::{Any, Expression, Fixed, VirtualCells};
use halo2_proofs::poly::Rotation;
use itertools::Itertools;
use log::debug;
use eth_types::Field;
use gadgets::binary_number::BinaryNumberChip;
use gadgets::util::{and, Expr, not, or};
use crate::evm_circuit::util::constraint_builder::{BaseConstraintBuilder, ConstrainBuilderCommon};
use crate::evm_circuit::util::math_gadget::BinaryNumberGadget;
use crate::wasm_circuit::consts::{CONTROL_INSTRUCTIONS_BLOCK, CONTROL_INSTRUCTIONS_WITH_LEB_ARG, CONTROL_INSTRUCTIONS_WITHOUT_ARGS, ControlInstruction, NUMERIC_INSTRUCTIONS_WITH_LEB_ARG, NUMERIC_INSTRUCTIONS_WITHOUT_ARGS, NumericInstruction, VARIABLE_INSTRUCTIONS_WITH_LEB_ARG, VariableInstruction, WASM_BLOCK_END, WASM_BLOCKTYPE_DELIMITER};
use crate::wasm_circuit::error::Error;
use crate::wasm_circuit::leb128_circuit::circuit::LEB128Chip;
use crate::wasm_circuit::leb128_circuit::helpers::{leb128_compute_sn, leb128_compute_sn_recovered_at_position};
use crate::wasm_circuit::wasm_bytecode::bytecode::WasmBytecode;
use crate::wasm_circuit::wasm_bytecode::bytecode_table::WasmBytecodeTable;
use crate::wasm_circuit::wasm_sections::helpers::configure_check_for_transition;
use crate::wasm_circuit::wasm_sections::wasm_code_section::wasm_code_section_body::structs::{WasmCodeSectionAssignLebParams, WasmCodeSectionAssignType};

#[derive(Debug, Clone)]
pub struct WasmCodeSectionBodyConfig<F: Field> {
    pub q_enable: Column<Fixed>,
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
    pub is_blocktype_delimiter: Column<Fixed>,
    pub is_block_end: Column<Fixed>,

    pub leb128_chip: Rc<LEB128Chip<F>>,
    pub numeric_instructions_chip: Rc<BinaryNumberChip<F, NumericInstruction, 8>>,
    pub variable_instruction_chip: Rc<BinaryNumberChip<F, VariableInstruction, 8>>,
    pub control_instruction_chip: Rc<BinaryNumberChip<F, ControlInstruction, 8>>,

    _marker: PhantomData<F>,
}

impl<'a, F: Field> WasmCodeSectionBodyConfig<F>
{}

#[derive(Debug, Clone)]
pub struct WasmCodeSectionBodyChip<F: Field> {
    pub config: WasmCodeSectionBodyConfig<F>,
    _marker: PhantomData<F>,
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
    ) -> WasmCodeSectionBodyConfig<F> {
        let q_enable = cs.fixed_column();
        let is_funcs_count = cs.fixed_column();
        let is_func_body_len = cs.fixed_column();
        let is_local_type_transitions_count = cs.fixed_column();
        let is_local_repetition_count = cs.fixed_column();
        let is_local_type = cs.fixed_column();

        let is_numeric_instruction = cs.fixed_column();
        let is_numeric_instruction_leb_arg = cs.fixed_column();
        let is_variable_instruction = cs.fixed_column();
        let is_variable_instruction_leb_arg = cs.fixed_column();
        let is_control_instruction = cs.fixed_column();
        let is_control_instruction_leb_arg = cs.fixed_column();
        let is_blocktype_delimiter = cs.fixed_column();
        let is_block_end = cs.fixed_column();

        let binary_number_config = BinaryNumberChip::configure(
            cs,
            is_numeric_instruction,
            Some(bytecode_table.value.into()),
        );
        let numeric_instructions_chip = Rc::new(BinaryNumberChip::construct(binary_number_config));

        let binary_number_config = BinaryNumberChip::configure(
            cs,
            is_control_instruction,
            Some(bytecode_table.value.into()),
        );
        let control_instruction_chip = Rc::new(BinaryNumberChip::construct(binary_number_config));

        let binary_number_config = BinaryNumberChip::configure(
            cs,
            is_variable_instruction,
            Some(bytecode_table.value.into()),
        );
        let variable_instruction_chip = Rc::new(BinaryNumberChip::construct(binary_number_config));

        cs.create_gate("WasmCodeSectionBody gate", |vc| {
            let mut cb = BaseConstraintBuilder::default();

            let q_enable_expr = vc.query_fixed(q_enable, Rotation::cur());
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
            let is_blocktype_delimiter_expr = vc.query_fixed(is_blocktype_delimiter, Rotation::cur());
            let is_block_end_expr = vc.query_fixed(is_block_end, Rotation::cur());

            let is_leb128_expr = vc.query_fixed(leb128_chip.config.q_enable, Rotation::cur());
            let is_leb128_next_expr = vc.query_fixed(leb128_chip.config.q_enable, Rotation::next());

            let byte_val_expr = vc.query_advice(bytecode_table.value, Rotation::cur());

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

            let is_numeric_opcode_without_params_expr = or::expr(
                NUMERIC_INSTRUCTIONS_WITHOUT_ARGS.iter()
                    .map(|v| {
                        numeric_instructions_chip.config.value_equals(*v, Rotation::cur())(vc)
                    }).collect_vec()
            );
            let is_numeric_opcode_with_leb_param_expr = or::expr(
                NUMERIC_INSTRUCTIONS_WITH_LEB_ARG.iter()
                    .map(|v| {
                        numeric_instructions_chip.config.value_equals(*v, Rotation::cur())(vc)
                    }).collect_vec()
            );
            let is_variable_opcode_with_leb_param_expr = or::expr(
                VARIABLE_INSTRUCTIONS_WITH_LEB_ARG.iter()
                    .map(|v| {
                        variable_instruction_chip.config.value_equals(*v, Rotation::cur())(vc)
                    }).collect_vec()
            );
            let is_control_opcode_without_params_expr = or::expr(
                CONTROL_INSTRUCTIONS_WITHOUT_ARGS.iter()
                    .map(|v| {
                        control_instruction_chip.config.value_equals(*v, Rotation::cur())(vc)
                    }).collect_vec()
            );
            let is_control_opcode_with_leb_param_expr = or::expr(
                CONTROL_INSTRUCTIONS_WITH_LEB_ARG.iter()
                    .map(|v| {
                        control_instruction_chip.config.value_equals(*v, Rotation::cur())(vc)
                    }).collect_vec()
            );
            let is_control_opcode_block_expr = or::expr(
                CONTROL_INSTRUCTIONS_BLOCK.iter()
                    .map(|v| {
                        control_instruction_chip.config.value_equals(*v, Rotation::cur())(vc)
                    }).collect_vec()
            );

            let is_opcode_with_leb_param_expr = or::expr([
                is_numeric_opcode_with_leb_param_expr.clone(),
                is_variable_opcode_with_leb_param_expr.clone(),
                is_control_opcode_with_leb_param_expr.clone(),
            ]);
            let is_instruction_expr = or::expr([
                is_numeric_instruction_expr.clone(),
                is_variable_instruction_expr.clone(),
                is_control_instruction_expr.clone(),
            ]);
            let is_instruction_leb_arg_expr = or::expr([
                is_numeric_instruction_leb_arg_expr.clone(),
                is_variable_instruction_leb_arg_expr.clone(),
                is_control_instruction_leb_arg_expr.clone(),
            ]);

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
                    + is_blocktype_delimiter_expr.clone()
                    + is_block_end_expr.clone(),
                1.expr(),
            );

            // is_funcs_count+ -> func+(is_func_body_len+ -> locals(1)(is_local_type_transitions_count+ -> local_var_descriptor+(is_local_repetition_count+ -> is_local_type(1))) -> is_func_body_code+)
            configure_check_for_transition(
                &mut cb,
                vc,
                "check next: is_funcs_count+ -> func+(is_func_body_len+ ...",
                is_funcs_count_expr.clone(),
                true,
                &[is_funcs_count, is_func_body_len, ],
            );
            configure_check_for_transition(
                &mut cb,
                vc,
                "check prev: is_funcs_count+ -> func+(is_func_body_len+ ...",
                is_func_body_len_expr.clone(),
                false,
                &[is_funcs_count, is_block_end, is_func_body_len, ],
            );
            configure_check_for_transition(
                &mut cb,
                vc,
                "check next: is_func_body_len+ -> locals(1)(is_local_type_transitions_count+ ...",
                is_func_body_len_expr.clone(),
                true,
                &[is_func_body_len, is_local_type_transitions_count, ],
            );
            configure_check_for_transition(
                &mut cb,
                vc,
                "check prev: is_func_body_len+ -> locals(1)(is_local_type_transitions_count+ ...",
                is_local_type_transitions_count_expr.clone(),
                false,
                &[is_func_body_len, is_local_type_transitions_count, ],
            );
            configure_check_for_transition(
                &mut cb,
                vc,
                "check next: is_local_type_transitions_count+ -> local_var_descriptor+(is_local_repetition_count+ ...",
                is_local_type_transitions_count_expr.clone(),
                true,
                &[is_local_type_transitions_count, is_local_repetition_count, ],
            );
            configure_check_for_transition(
                &mut cb,
                vc,
                "check prev: is_local_type_transitions_count+ -> local_var_descriptor+(is_local_repetition_count+ ...",
                is_local_repetition_count_expr.clone(),
                false,
                &[is_local_type_transitions_count, is_local_type, is_local_repetition_count, ],
            );
            configure_check_for_transition(
                &mut cb,
                vc,
                "check next: is_local_repetition_count+ -> is_local_type(1) ...",
                is_local_repetition_count_expr.clone(),
                true,
                &[is_local_repetition_count, is_local_type, ],
            );
            configure_check_for_transition(
                &mut cb,
                vc,
                "check prev: is_local_repetition_count+ -> is_local_type(1) ...",
                is_local_type_expr.clone(),
                false,
                &[is_local_repetition_count, ],
            );
            configure_check_for_transition(
                &mut cb,
                vc,
                "check next: ... is_local_type(1))) -> is_func_body_code+",
                is_local_type_expr.clone(),
                true,
                &[is_local_repetition_count, is_numeric_instruction, is_variable_instruction, is_control_instruction, ],
            );
            configure_check_for_transition(
                &mut cb,
                vc,
                "check prev: ... is_local_type(1))) -> is_func_body_code+",
                is_instruction_expr.clone(),
                false,
                &[
                    is_local_type,
                    is_numeric_instruction,
                    is_variable_instruction,
                    is_control_instruction,
                    is_numeric_instruction_leb_arg,
                    is_variable_instruction_leb_arg,
                    is_control_instruction_leb_arg,
                    is_blocktype_delimiter,
                    is_block_end,
                ],
            );

            // BASIC CONSTRAINTS:

            // is_numeric_instruction(1) => opcode is valid
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

            // is_variable_instruction(1) => opcode is valid
            cb.condition(
                is_variable_instruction_expr.clone(),
                |bcb| {
                    bcb.require_equal(
                        "is_variable_instruction(1) => opcode is valid",
                        or::expr(
                            VARIABLE_INSTRUCTIONS_WITH_LEB_ARG.iter()
                                .map(|v| {
                                    variable_instruction_chip.config.value_equals(*v, Rotation::cur())(vc)
                                }).collect_vec()
                        ),
                        1.expr(),
                    );
                }
            );

            // is_control_instruction(1) => opcode is valid
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

            // leb128 flag is active => leb128_chip enabled
            cb.condition(
                or::expr([
                    is_funcs_count_expr.clone(),
                    is_func_body_len_expr.clone(),
                    is_local_type_transitions_count_expr.clone(),
                    is_local_repetition_count_expr.clone(),
                    is_instruction_leb_arg_expr.clone(),
                ]),
                |cbc| {
                    cbc.require_equal(
                        "leb128 flag is active => leb128_chip enabled",
                        is_leb128_expr.clone(),
                        1.expr(),
                    )
                }
            );
            // is_blocktype_delimiter(1) => WASM_BLOCKTYPE_DELIMITER
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
            // is_block_end(1) => WASM_BLOCK_END
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

            // is_numeric_opcode_with_leb_param(1) -> is_numeric_instruction_leb_arg+
            cb.condition(
                is_numeric_opcode_with_leb_param_expr.clone(),
                |bcb| {
                    bcb.require_equal(
                        "is_numeric_opcode_with_leb_param(1) -> is_leb128",
                        is_leb128_next_expr.clone(),
                        1.expr(),
                    );
                }
            );

            // is_variable_opcode_with_leb_param(1) -> is_variable_instruction_leb_arg+
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

            // is_control_opcode_with_leb_param(1) -> is_control_instruction_leb_arg+
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
            // is_control_opcode_block(1) -> is_blocktype_delimiter(1)
            configure_check_for_transition(
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

            // TODO need reversed-direction constraints

            // is_numeric_instruction(1) -> is_instruction_leb_arg || is_instruction || is_block_end
            cb.condition(
                is_numeric_instruction_expr.clone(),
                |bcb| {
                    let is_numeric_instruction_leb_arg_next_expr = vc.query_fixed(is_numeric_instruction_leb_arg, Rotation::next());
                    let is_variable_instruction_leb_arg_next_expr = vc.query_fixed(is_variable_instruction_leb_arg, Rotation::next());
                    let is_control_instruction_leb_arg_next_expr = vc.query_fixed(is_control_instruction_leb_arg, Rotation::next());

                    let is_numeric_instruction_next_expr = vc.query_fixed(is_numeric_instruction, Rotation::next());
                    let is_variable_instruction_next_expr = vc.query_fixed(is_variable_instruction, Rotation::next());
                    let is_control_instruction_next_expr = vc.query_fixed(is_control_instruction, Rotation::next());

                    let is_block_end_next_expr = vc.query_fixed(is_block_end, Rotation::next());

                    bcb.require_equal(
                        "check next: is_numeric_instruction(1) -> is_instruction_leb_arg || is_instruction || is_block_end",
                        is_numeric_instruction_leb_arg_next_expr
                            + is_variable_instruction_leb_arg_next_expr
                            + is_control_instruction_leb_arg_next_expr

                            + is_numeric_instruction_next_expr
                            + is_variable_instruction_next_expr
                            + is_control_instruction_next_expr

                            + is_block_end_next_expr
                        ,
                        1.expr(),
                    );
                }
            );

            // is_variable_instruction(1) -> is_instruction_leb_arg || is_instruction || is_block_end
            cb.condition(
                is_variable_instruction_expr.clone(),
                |bcb| {
                    let is_numeric_instruction_leb_arg_next_expr = vc.query_fixed(is_numeric_instruction_leb_arg, Rotation::next());
                    let is_variable_instruction_leb_arg_next_expr = vc.query_fixed(is_variable_instruction_leb_arg, Rotation::next());
                    let is_control_instruction_leb_arg_next_expr = vc.query_fixed(is_control_instruction_leb_arg, Rotation::next());

                    let is_numeric_instruction_next_expr = vc.query_fixed(is_numeric_instruction, Rotation::next());
                    let is_variable_instruction_next_expr = vc.query_fixed(is_variable_instruction, Rotation::next());
                    let is_control_instruction_next_expr = vc.query_fixed(is_control_instruction, Rotation::next());

                    let is_block_end_next_expr = vc.query_fixed(is_block_end, Rotation::next());

                    bcb.require_equal(
                        "check next: is_variable_instruction(1) -> is_instruction_leb_arg || is_instruction || is_block_end",
                        is_numeric_instruction_leb_arg_next_expr
                            + is_variable_instruction_leb_arg_next_expr
                            + is_control_instruction_leb_arg_next_expr

                            + is_numeric_instruction_next_expr
                            + is_variable_instruction_next_expr
                            + is_control_instruction_next_expr

                            + is_block_end_next_expr
                        ,
                        1.expr(),
                    );
                }
            );

            // is_control_instruction(1) && not(is_control_opcode_block) -> is_instruction_leb_arg || is_instruction || is_block_end
            cb.condition(
                and::expr([
                    is_control_instruction_expr.clone(),
                    not::expr(is_control_opcode_block_expr.clone()),
                ]),
                |bcb| {
                    let is_numeric_instruction_leb_arg_next_expr = vc.query_fixed(is_numeric_instruction_leb_arg, Rotation::next());
                    let is_variable_instruction_leb_arg_next_expr = vc.query_fixed(is_variable_instruction_leb_arg, Rotation::next());
                    let is_control_instruction_leb_arg_next_expr = vc.query_fixed(is_control_instruction_leb_arg, Rotation::next());

                    let is_numeric_instruction_next_expr = vc.query_fixed(is_numeric_instruction, Rotation::next());
                    let is_variable_instruction_next_expr = vc.query_fixed(is_variable_instruction, Rotation::next());
                    let is_control_instruction_next_expr = vc.query_fixed(is_control_instruction, Rotation::next());

                    let is_block_end_next_expr = vc.query_fixed(is_block_end, Rotation::next());

                    bcb.require_equal(
                        "check next: is_control_instruction(1) && not(is_control_opcode_block) -> is_instruction_leb_arg || is_instruction || is_block_end",
                        is_numeric_instruction_leb_arg_next_expr
                            + is_variable_instruction_leb_arg_next_expr
                            + is_control_instruction_leb_arg_next_expr

                            + is_numeric_instruction_next_expr
                            + is_variable_instruction_next_expr
                            + is_control_instruction_next_expr

                            + is_block_end_next_expr
                        ,
                        1.expr(),
                    );
                }
            );

            cb.gate(q_enable_expr.clone())
        });

        let config = WasmCodeSectionBodyConfig::<F> {
            q_enable,
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
            is_blocktype_delimiter,
            is_block_end,
            leb128_chip,
            numeric_instructions_chip,
            variable_instruction_chip,
            control_instruction_chip,
            _marker: PhantomData,
        };

        config
    }

    pub fn assign(
        &self,
        region: &mut Region<F>,
        wasm_bytecode: &WasmBytecode,
        offset: usize,
        assign_type: WasmCodeSectionAssignType,
        assign_value: bool,
        leb_params: Option<WasmCodeSectionAssignLebParams>,
    ) {
        if assign_type == WasmCodeSectionAssignType::Unknown { panic!("unknown assign type") }
        let q_enable = true;
        let assign_value = assign_value as u64;
        debug!(
            "assign at offset {} \
            q_enable {} \
            assign_type {:?} \
            ",
            offset,
            q_enable,
            assign_type,
        );
        match assign_type {
            WasmCodeSectionAssignType::FuncsCount |
            WasmCodeSectionAssignType::FuncBodyLen |
            WasmCodeSectionAssignType::LocalTypeTransitionsCount |
            WasmCodeSectionAssignType::LocalRepetitionCount |
            WasmCodeSectionAssignType::NumericInstructionLebArg |
            WasmCodeSectionAssignType::VariableInstructionLebArg |
            WasmCodeSectionAssignType::ControlInstructionLebArg => {
                let leb_params = leb_params.unwrap();
                let is_first_leb_byte = leb_params.byte_rel_offset == 0;
                let is_last_leb_byte = leb_params.byte_rel_offset == leb_params.last_byte_rel_offset;
                let is_leb_byte_has_cb = leb_params.byte_rel_offset < leb_params.last_byte_rel_offset;
                self.config.leb128_chip.assign(
                    region,
                    offset,
                    leb_params.byte_rel_offset,
                    q_enable,
                    is_first_leb_byte,
                    is_last_leb_byte,
                    is_leb_byte_has_cb,
                    false,
                    leb_params.sn,
                    leb_params.sn_recovered_at_pos,
                );
            }
            _ => {}
        }
        region.assign_fixed(
            || format!("assign 'q_enable' val {} at {}", q_enable, offset),
            self.config.q_enable,
            offset,
            || Value::known(F::from(q_enable as u64)),
        ).unwrap();
        match assign_type {
            WasmCodeSectionAssignType::FuncsCount => {
                region.assign_fixed(
                    || format!("assign 'is_funcs_count' val {} at {}", assign_value, offset),
                    self.config.is_funcs_count,
                    offset,
                    || Value::known(F::from(assign_value)),
                ).unwrap();
            }
            WasmCodeSectionAssignType::FuncBodyLen => {
                region.assign_fixed(
                    || format!("assign 'is_func_body_len' val {} at {}", assign_value, offset),
                    self.config.is_func_body_len,
                    offset,
                    || Value::known(F::from(assign_value)),
                ).unwrap();
            }
            WasmCodeSectionAssignType::LocalTypeTransitionsCount => {
                region.assign_fixed(
                    || format!("assign 'is_local_type_transitions_count' val {} at {}", assign_value, offset),
                    self.config.is_local_type_transitions_count,
                    offset,
                    || Value::known(F::from(assign_value)),
                ).unwrap();
            }
            WasmCodeSectionAssignType::LocalRepetitionCount => {
                region.assign_fixed(
                    || format!("assign 'is_local_repetition_count' val {} at {}", assign_value, offset),
                    self.config.is_local_repetition_count,
                    offset,
                    || Value::known(F::from(assign_value)),
                ).unwrap();
            }
            WasmCodeSectionAssignType::LocalType => {
                region.assign_fixed(
                    || format!("assign 'is_local_type' val {} at {}", assign_value, offset),
                    self.config.is_local_type,
                    offset,
                    || Value::known(F::from(assign_value)),
                ).unwrap();
            }
            WasmCodeSectionAssignType::NumericInstruction => {
                region.assign_fixed(
                    || format!("assign 'is_numeric_instruction' val {} at {}", assign_value, offset),
                    self.config.is_numeric_instruction,
                    offset,
                    || Value::known(F::from(assign_value)),
                ).unwrap();
                if assign_value == 1 {
                    let opcode = (wasm_bytecode.bytes[offset] as i32).try_into().unwrap();
                    self.config.numeric_instructions_chip.assign(
                        region,
                        offset,
                        &opcode,
                    ).unwrap();
                }
            }
            WasmCodeSectionAssignType::NumericInstructionLebArg => {
                region.assign_fixed(
                    || format!("assign 'is_numeric_instruction_leb_arg' val {} at {}", assign_value, offset),
                    self.config.is_numeric_instruction_leb_arg,
                    offset,
                    || Value::known(F::from(assign_value)),
                ).unwrap();
            }
            WasmCodeSectionAssignType::VariableInstruction => {
                region.assign_fixed(
                    || format!("assign 'is_variable_instruction' val {} at {}", assign_value, offset),
                    self.config.is_variable_instruction,
                    offset,
                    || Value::known(F::from(assign_value)),
                ).unwrap();
                if assign_value == 1 {
                    let opcode = (wasm_bytecode.bytes[offset] as i32).try_into().unwrap();
                    self.config.variable_instruction_chip.assign(
                        region,
                        offset,
                        &opcode,
                    ).unwrap();
                }
            }
            WasmCodeSectionAssignType::VariableInstructionLebArg => {
                region.assign_fixed(
                    || format!("assign 'is_variable_instruction_leb_arg' val {} at {}", assign_value, offset),
                    self.config.is_variable_instruction_leb_arg,
                    offset,
                    || Value::known(F::from(assign_value)),
                ).unwrap();
            }
            WasmCodeSectionAssignType::ControlInstruction => {
                region.assign_fixed(
                    || format!("assign 'is_control_instruction' val {} at {}", assign_value, offset),
                    self.config.is_control_instruction,
                    offset,
                    || Value::known(F::from(assign_value)),
                ).unwrap();
                if assign_value == 1 {
                    let opcode = (wasm_bytecode.bytes[offset] as i32).try_into().unwrap();
                    self.config.control_instruction_chip.assign(
                        region,
                        offset,
                        &opcode,
                    ).unwrap();
                }
            }
            WasmCodeSectionAssignType::ControlInstructionLebArg => {
                region.assign_fixed(
                    || format!("assign 'is_control_instruction_leb_arg' val {} at {}", assign_value, offset),
                    self.config.is_control_instruction_leb_arg,
                    offset,
                    || Value::known(F::from(assign_value)),
                ).unwrap();
            }
            WasmCodeSectionAssignType::BlocktypeDelimiter => {
                region.assign_fixed(
                    || format!("assign 'is_blocktype_delimiter' val {} at {}", assign_value, offset),
                    self.config.is_blocktype_delimiter,
                    offset,
                    || Value::known(F::from(assign_value)),
                ).unwrap();
            }
            WasmCodeSectionAssignType::BlockEnd => {
                region.assign_fixed(
                    || format!("assign 'is_block_end' val {} at {}", assign_value, offset),
                    self.config.is_block_end,
                    offset,
                    || Value::known(F::from(assign_value)),
                ).unwrap();
            }
            WasmCodeSectionAssignType::Unknown => {}
        }
    }

    /// returns sn and leb len
    fn markup_leb_section(
        &self,
        region: &mut Region<F>,
        wasm_bytecode: &WasmBytecode,
        leb_bytes_start_offset: usize,
        assign_type: WasmCodeSectionAssignType,
        assign_value: bool,
    ) -> (u64, usize) {
        match assign_type {
            WasmCodeSectionAssignType::FuncsCount |
            WasmCodeSectionAssignType::FuncBodyLen |
            WasmCodeSectionAssignType::LocalTypeTransitionsCount |
            WasmCodeSectionAssignType::LocalRepetitionCount |
            WasmCodeSectionAssignType::NumericInstructionLebArg |
            WasmCodeSectionAssignType::VariableInstructionLebArg |
            WasmCodeSectionAssignType::ControlInstructionLebArg => {}
            _ => { panic!("unsupported assign_type {:?}", assign_type) }
        }
        const OFFSET: usize = 0;
        let (leb_sn, last_byte_offset) = leb128_compute_sn(&wasm_bytecode.bytes[leb_bytes_start_offset..], false, OFFSET).unwrap();
        let mut leb_sn_recovered_at_pos = 0;
        for byte_offset in OFFSET..=last_byte_offset {
            let offset = leb_bytes_start_offset + byte_offset;
            leb_sn_recovered_at_pos = leb128_compute_sn_recovered_at_position(
                leb_sn_recovered_at_pos,
                false,
                byte_offset,
                last_byte_offset,
                wasm_bytecode.bytes[offset],
            );
            self.assign(
                region,
                wasm_bytecode,
                offset,
                assign_type,
                assign_value,
                Some(WasmCodeSectionAssignLebParams{
                    byte_rel_offset: byte_offset,
                    last_byte_rel_offset: last_byte_offset,
                    sn: leb_sn,
                    sn_recovered_at_pos: leb_sn_recovered_at_pos,
                })
            );
        }

        (leb_sn, last_byte_offset + 1)
    }

    /// returns new offset
    fn markup_instruction_section(
        &self,
        region: &mut Region<F>,
        wasm_bytecode: &WasmBytecode,
        start_offset: usize,
    ) -> Result<usize, Error> {
        let mut offset = start_offset;

        let opcode = wasm_bytecode.bytes[offset] as i32;

        let mut assign_type = WasmCodeSectionAssignType::Unknown;
        let mut assign_type_argument = WasmCodeSectionAssignType::Unknown;


        if let Ok(opcode) = <i32 as TryInto<NumericInstruction>>::try_into(opcode) {
            assign_type = WasmCodeSectionAssignType::NumericInstruction;
            if NUMERIC_INSTRUCTIONS_WITH_LEB_ARG.contains(&opcode) {
                assign_type_argument = WasmCodeSectionAssignType::NumericInstructionLebArg;
            }
        }

        if let Ok(opcode) = <i32 as TryInto<VariableInstruction>>::try_into(opcode) {
            assign_type = WasmCodeSectionAssignType::VariableInstruction;
            if VARIABLE_INSTRUCTIONS_WITH_LEB_ARG.contains(&opcode) {
                assign_type_argument = WasmCodeSectionAssignType::VariableInstructionLebArg;
            }
        }

        if let Ok(opcode) = <i32 as TryInto<ControlInstruction>>::try_into(opcode) {
            assign_type = WasmCodeSectionAssignType::ControlInstruction;
            if CONTROL_INSTRUCTIONS_BLOCK.contains(&opcode) {
                assign_type_argument = WasmCodeSectionAssignType::BlocktypeDelimiter
            }
            if CONTROL_INSTRUCTIONS_WITH_LEB_ARG.contains(&opcode) {
                assign_type_argument = WasmCodeSectionAssignType::ControlInstructionLebArg
            }
        }

        if opcode == WASM_BLOCK_END {
            assign_type = WasmCodeSectionAssignType::BlockEnd;
        };

        if assign_type == WasmCodeSectionAssignType::NumericInstruction
            || assign_type == WasmCodeSectionAssignType::VariableInstruction
            || assign_type == WasmCodeSectionAssignType::ControlInstruction
            || assign_type == WasmCodeSectionAssignType::BlockEnd
        {
            self.assign(
                region,
                wasm_bytecode,
                offset,
                assign_type,
                true,
                None,
            );
            offset += 1;
        }

        if assign_type_argument == WasmCodeSectionAssignType::BlocktypeDelimiter {
            self.assign(
                region,
                wasm_bytecode,
                offset,
                assign_type_argument,
                true,
                None,
            );
            offset += 1;
        }

        if assign_type_argument == WasmCodeSectionAssignType::NumericInstructionLebArg
            || assign_type_argument == WasmCodeSectionAssignType::VariableInstructionLebArg
            || assign_type_argument == WasmCodeSectionAssignType::ControlInstructionLebArg {
            let (instruction_leb_argument, instruction_leb_argument_leb_len) = self.markup_leb_section(
                region,
                wasm_bytecode,
                offset,
                assign_type_argument,
                true,
            );
            debug!(
                "offset {} \
                assign_type_argument {:?} \
                instruction_leb_argument {} \
                instruction_leb_argument_leb_len {} \
                ",
                offset,
                assign_type_argument,
                instruction_leb_argument,
                instruction_leb_argument_leb_len,
            );
            offset += instruction_leb_argument_leb_len;
        }

        if offset == start_offset {
            panic!("failed to detect instruction at offset {}", offset)
        }

        Ok(offset)
    }

    /// returns new offset
    pub fn assign_auto(
        &self,
        region: &mut Region<F>,
        wasm_bytecode: &WasmBytecode,
        offset_start: usize,
    ) -> Result<usize, Error> {
        let mut offset = offset_start;
        debug!("offset_start {}", offset);

        // is_funcs_count+
        let (funcs_count, funcs_count_leb_len) = self.markup_leb_section(
            region,
            wasm_bytecode,
            offset,
            WasmCodeSectionAssignType::FuncsCount,
            true,
        );
        debug!("offset {} funcs_count {} funcs_count_leb_len {}", offset, funcs_count, funcs_count_leb_len);
        offset += funcs_count_leb_len;

        for _func_index in 0..funcs_count {
            // is_func_body_len+
            let (func_body_len, func_body_len_leb_len) = self.markup_leb_section(
                region,
                wasm_bytecode,
                offset,
                WasmCodeSectionAssignType::FuncBodyLen,
                true,
            );
            let func_body_start_offset = offset;
            debug!("offset {} func_body_len {} func_body_len_leb_len {} func_body_start_offset {}", offset, func_body_len, func_body_len_leb_len, func_body_start_offset);
            offset += func_body_len_leb_len;

            let func_body_end_offset = offset + (func_body_len as usize) - 1;
            debug!("offset {} func_body_end_offset {}", offset, func_body_end_offset);

            //  locals(1)(is_local_type_transitions_count+ ...
            let (is_local_type_transitions_count, is_local_type_transitions_count_leb_len) = self.markup_leb_section(
                region,
                wasm_bytecode,
                offset,
                WasmCodeSectionAssignType::LocalTypeTransitionsCount,
                true,
            );
            debug!("offset {} is_local_type_transitions_count {} is_local_type_transitions_count_leb_len {}", offset, is_local_type_transitions_count, is_local_type_transitions_count_leb_len);
            offset += is_local_type_transitions_count_leb_len;

            for is_valtype_transition_index in 0..is_local_type_transitions_count {
                // -> local_var_descriptor+(is_local_repetition_count+ ...
                let (is_local_repetition_count, is_local_repetition_count_leb_len) = self.markup_leb_section(
                    region,
                    wasm_bytecode,
                    offset,
                    WasmCodeSectionAssignType::LocalRepetitionCount,
                    true,
                );
                debug!("offset {} is_local_repetition_count {} is_local_repetition_count_leb_len {}", offset, is_local_repetition_count, is_local_repetition_count_leb_len);
                offset += is_local_repetition_count_leb_len;

                // is_local_type(1)
                self.assign(
                    region,
                    wasm_bytecode,
                    offset,
                    WasmCodeSectionAssignType::LocalType,
                    true,
                    None,
                );
                debug!("offset {} is_local_type true", offset);
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

        Ok(offset)
    }
}