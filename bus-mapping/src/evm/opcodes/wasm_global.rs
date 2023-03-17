use eth_types::GethExecStep;

use crate::circuit_input_builder::{CircuitInputStateRef, ExecStep};
use crate::Error;

use super::Opcode;

///
#[derive(Debug, Copy, Clone)]
pub(crate) struct WasmGlobalOpcode<const IS_WRITE: bool>;

impl<const IS_WRITE: bool> Opcode for WasmGlobalOpcode<IS_WRITE> {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        geth_steps: &[GethExecStep],
    ) -> Result<Vec<ExecStep>, Error> {
        let current_step = &geth_steps[0];
        let next_step = &geth_steps[1];

        let mut exec_step = state.new_step(current_step)?;

        let global_index = current_step.params[0];
        if IS_WRITE {
            let value = current_step.stack.nth_last(0)?;
            state.stack_read(&mut exec_step, current_step.stack.nth_last_filled(0), value)?;
            state.global_write(&mut exec_step, global_index as u32, value)?;
        } else {
            let value = next_step.stack.nth_last(0)?;
            state.global_read(&mut exec_step, global_index as u32, value)?;
            state.stack_write(&mut exec_step, next_step.stack.nth_last_filled(0), value)?;
        }

        Ok(vec![exec_step])
    }
}
