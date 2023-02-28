use ethers_core::k256::pkcs8::der::Encode;
use eth_types::evm_types::MemoryAddress;
use crate::{
    circuit_input_builder::{CircuitInputStateRef, ExecStep},
    Error,
};

use eth_types::GethExecStep;

use super::Opcode;

pub const CODE_SIZE_BYTE_LENGTH: usize = 4;

#[derive(Clone, Copy, Debug)]
pub(crate) struct Codesize;

impl Opcode for Codesize {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        geth_steps: &[GethExecStep],
    ) -> Result<Vec<ExecStep>, Error> {
        let geth_step = &geth_steps[0];
        let geth_second_step = &geth_steps[1];
        let mut exec_step = state.new_step(geth_step)?;

        let code_hash = state.call()?.code_hash;
        let code = state.code(code_hash)?;
        let codesize = code.len() as i32;
        let codesize_bytes = codesize.to_vec().unwrap();

        // debug_assert_eq!(codesize, geth_steps[1].stack.last()?.as_usize());

        // Read dest offset as the last stack element
        let dest_offset = geth_step.stack.nth_last(0)?;
        state.stack_read(&mut exec_step, geth_step.stack.nth_last_filled(0), dest_offset)?;
        let offset_addr = MemoryAddress::try_from(dest_offset)?;

        // Copy result to memory
        for i in 0..CODE_SIZE_BYTE_LENGTH {
            state.memory_write(&mut exec_step, offset_addr.map(|a| a + i), codesize_bytes[i])?;
        }
        let call_ctx = state.call_ctx_mut()?;
        call_ctx.memory = geth_second_step.memory.clone();

        Ok(vec![exec_step])
    }
}

#[cfg(test)]
mod codesize_tests {
    use eth_types::{bytecode, Bytecode, evm_types::{OpcodeId, StackAddress}, geth_types::GethData, Word};
    use mock::{
        test_ctx::helpers::{account_0_code_account_1_no_code, tx_from_1_to_0},
        TestContext,
    };

    use crate::{
        circuit_input_builder::ExecState,
        mocks::BlockData,
        operation::{StackOp, RW},
    };
    use crate::evm::opcodes::codesize::CODE_SIZE_BYTE_LENGTH;

    fn test_ok(large: bool) {
        let res_mem_address = 0x7f;
        let mut code = bytecode! {};
        let st_addr = 1023;
        let tail: Bytecode;
        if large {
            code.append(&bytecode! {
                I32Const[res_mem_address]
                I32Const[res_mem_address]
                I32Add
            });
            for i in 1..10 {
                if i%2 == 1 {
                    code.append(&bytecode! {
                        I32Const[-res_mem_address]
                        I32Add
                    });
                } else {
                    code.append(&bytecode! {
                        I32Const[res_mem_address]
                        I32Add
                    });
                }
                // st_addr -= 128;
            }
            tail = bytecode! {
                CODESIZE
            };
        } else {
            tail = bytecode! {
                I32Const[res_mem_address]
                CODESIZE
            };
        }
        code.append(&tail);

        let block: GethData = TestContext::<2, 1>::new(
            None,
            account_0_code_account_1_no_code(code, None),
            tx_from_1_to_0,
            |block, _tx| block.number(0xcafeu64),
        )
        .unwrap()
        .into();

        let mut builder = BlockData::new_from_geth_data(block.clone()).new_circuit_input_builder();
        builder
            .handle_block(&block.eth_block, &block.geth_traces)
            .unwrap();

        let step = builder.block.txs()[0]
            .steps()
            .iter()
            .find(|step| step.exec_state == ExecState::Op(OpcodeId::CODESIZE))
            .unwrap();

        assert_eq!(step.bus_mapping_instance.len(), CODE_SIZE_BYTE_LENGTH + 1);
        let op = &builder.block.container.stack[step.bus_mapping_instance[0].as_usize()];
        assert_eq!(op.rw(), RW::READ);
        assert_eq!(
            op.op(),
            &StackOp::new(1, StackAddress::from(st_addr), Word::from(res_mem_address))
        );
    }

    #[test]
    fn codesize_opcode1_impl() {
        test_ok(false);
    }

    // #[test]
    // fn codesize_opcode2_impl() {
    //     test_ok(true);
    // }
}
