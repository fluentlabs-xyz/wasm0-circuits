use eth_types::{GethExecStep};
use eth_types::evm_types::OpcodeId;

use crate::circuit_input_builder::{CircuitInputStateRef, ExecStep};
use crate::Error;

use super::Opcode;

///
#[derive(Debug, Copy, Clone)]
pub(crate) struct WasmBreakOpcode;

impl Opcode for WasmBreakOpcode {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        geth_steps: &[GethExecStep],
    ) -> Result<Vec<ExecStep>, Error> {
        let current_step = &geth_steps[0];
        let _next_step = &geth_steps[1];

        let exec_step = state.new_step(current_step)?;

        match current_step.op {
            OpcodeId::Return => {
            }
            OpcodeId::Br => {
            }
            OpcodeId::BrIf => {
            }
            OpcodeId::BrTable => {
            }
            _ => unreachable!("not supported opcode: {:?}", current_step.op)
        };

        Ok(vec![exec_step])
    }
}
