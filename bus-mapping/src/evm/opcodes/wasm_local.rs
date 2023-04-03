use eth_types::evm_types::OpcodeId;
use eth_types::{GethExecStep};

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

        // when first time local access happen that's index out of function args then it pushes
        // puts zero value on the top of the stack
        // let sorted_stack = state.block.container.sorted_stack();
        // if sorted_stack.len() == 0 {
        //     state.stack_write(&mut exec_step, current_step.stack.nth_last_filled(1), StackWord::zero())?;
        // }

        match current_step.op {
            OpcodeId::SetLocal => {
                let value = current_step.stack.nth_last(0)?;
                state.stack_read(&mut exec_step, current_step.stack.nth_last_filled(0), value)?;
                state.local_write(&mut exec_step, current_step.stack.nth_last_filled(local_index), local_index, value)?;
            }
            OpcodeId::GetLocal => {
                let value = next_step.stack.nth_last(local_index)?;
                state.local_read(&mut exec_step, current_step.stack.nth_last_filled(local_index), local_index, value)?;
                state.stack_write(&mut exec_step, next_step.stack.nth_last_filled(0), value)?;
            }
            OpcodeId::TeeLocal => {
                let value = current_step.stack.nth_last(0)?;
                state.stack_read(&mut exec_step, current_step.stack.nth_last_filled(0), value)?;
                state.local_write(&mut exec_step, current_step.stack.nth_last_filled(local_index), local_index, value)?;
                state.stack_write(&mut exec_step, next_step.stack.nth_last_filled(0), value)?;
            }
            _ => unreachable!("not supported opcode: {:?}", current_step.op)
        };

        Ok(vec![exec_step])
    }
}
