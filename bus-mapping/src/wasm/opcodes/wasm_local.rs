use eth_types::GethExecStep;
use eth_types::evm_types::OpcodeId;

use crate::circuit_input_builder::{CircuitInputStateRef, ExecStep};
use crate::Error;

use super::Opcode;

///
#[derive(Debug, Copy, Clone)]
pub(crate) struct WasmLocalOpcode;

impl Opcode for WasmLocalOpcode {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        geth_steps: &[GethExecStep],
    ) -> Result<Vec<ExecStep>, Error> {
        let current_step = &geth_steps[0];
        let next_step = &geth_steps[1];

        let mut exec_step = state.new_step(current_step)?;

        let local_index = current_step.params[0] as usize;
        let local_offset = local_index - 1;

        match current_step.op {
            OpcodeId::SetLocal => {
                let value = current_step.stack.nth_last(0)?;
                state.stack_read(&mut exec_step, current_step.stack.nth_last_filled(0), value)?;
                state.local_write(&mut exec_step, next_step.stack.nth_last_filled(local_offset), local_offset, value)?;
            }
            OpcodeId::GetLocal => {
                let value = current_step.stack.nth_last(local_offset)?;
                state.local_read(&mut exec_step, current_step.stack.nth_last_filled(local_offset), local_offset, value)?;
                state.stack_write(&mut exec_step, next_step.stack.nth_last_filled(0), value)?;
            }
            OpcodeId::TeeLocal => {
                let value = current_step.stack.nth_last(0)?;
                state.stack_read(&mut exec_step, current_step.stack.nth_last_filled(0), value)?;
                state.local_write(&mut exec_step, next_step.stack.nth_last_filled(local_offset), local_offset, value)?;
                state.stack_write(&mut exec_step, next_step.stack.nth_last_filled(0), value)?;
            }
            _ => unreachable!("not supported opcode: {:?}", current_step.op)
        };

        Ok(vec![exec_step])
    }
}
