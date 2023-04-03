    use eth_types::{GethExecStep, ToU256, ToWord};
use eth_types::evm_types::OpcodeId;

use crate::circuit_input_builder::{CircuitInputStateRef, ExecStep};
use crate::Error;
use crate::operation::CallContextField;

use super::Opcode;

///
#[derive(Debug, Copy, Clone)]
pub(crate) struct WasmCallOpcode;

impl Opcode for WasmCallOpcode {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        geth_steps: &[GethExecStep],
    ) -> Result<Vec<ExecStep>, Error> {
        let current_step = &geth_steps[0];
        let next_step = &geth_steps[1];

        let mut exec_step = state.new_step(current_step)?;

        match current_step.op {
            OpcodeId::Call => {
                let call_index = current_step.params[0];
                let pc = next_step.pc;
                state.call_context_write(
                    &mut exec_step,
                    state.call()?.call_id,
                    CallContextField::InternalFunctionId,
                    call_index.to_word(),
                );
                state.call_context_write(
                    &mut exec_step,
                    state.call()?.call_id,
                    CallContextField::ProgramCounter,
                    pc.0.to_u256(),
                );
            }
            OpcodeId::CallIndirect => {

            }
            _ => unreachable!("not supported opcode: {:?}", current_step.op)
        };

        Ok(vec![exec_step])
    }
}
