use eth_types::evm_types::OpcodeId;
use eth_types::GethExecStep;

use crate::circuit_input_builder::{CircuitInputStateRef, ExecStep};
use crate::Error;

use super::Opcode;

#[derive(Debug, Copy, Clone)]
pub(crate) struct WasmTableOpcode<
    const N_POP: usize,
    const N_PUSH: usize,
    const IS_ERR: bool = { false },
>;

impl<const N_POP: usize, const N_PUSH: usize, const IS_ERR: bool> Opcode
for WasmTableOpcode<N_POP, N_PUSH, IS_ERR>
{
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        geth_steps: &[GethExecStep],
    ) -> Result<Vec<ExecStep>, Error> {
        let current_step = &geth_steps[0];
        let next_step = &geth_steps[1];

        let mut exec_step = state.new_step(current_step)?;

        let global_index = current_step.params[0];
        // TODO: fill opcodes
/*
        match current_step.op {
            OpcodeId::SetGlobal => {
                let value = current_step.stack.nth_last(0)?;
                state.stack_read(&mut exec_step, current_step.stack.nth_last_filled(0), value)?;
                state.global_write(&mut exec_step, global_index as u32, value)?;
            },
            OpcodeId::GetGlobal => {
                let value = next_step.stack.nth_last(0)?;
                state.global_read(&mut exec_step, global_index as u32, value)?;
                state.stack_write(&mut exec_step, next_step.stack.nth_last_filled(0), value)?;
            },
            _ => unreachable!("not supported opcode: {:?}", current_step.op)
        };
*/

        Ok(vec![exec_step])
    }
}
