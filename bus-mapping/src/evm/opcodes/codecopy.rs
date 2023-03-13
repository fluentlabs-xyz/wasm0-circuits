use crate::{
    circuit_input_builder::{
        CircuitInputStateRef, CopyDataType, CopyEvent, ExecStep, NumberOrHash,
    },
    Error,
};
use eth_types::{Bytecode, GethExecStep};

use super::Opcode;

#[derive(Clone, Copy, Debug)]
pub(crate) struct Codecopy;

impl Opcode for Codecopy {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        geth_steps: &[GethExecStep],
    ) -> Result<Vec<ExecStep>, Error> {
        let geth_step = &geth_steps[0];
        let exec_steps = vec![gen_codecopy_step(state, geth_step)?];

        let length = geth_step.stack.nth_last(0)?.as_u64();
        let code_offset = geth_step.stack.nth_last(1)?.as_u64();
        let dest_offset = geth_step.stack.nth_last(2)?.as_u64();

        let code_hash = state.call()?.code_hash;
        let code = state.code(code_hash)?;

        let call_ctx = state.call_ctx_mut()?;
        let memory = &mut call_ctx.memory;

        memory.copy_from(dest_offset, &code, code_offset, length as usize);

        let copy_event = gen_copy_event(state, geth_step)?;
        state.push_copy(copy_event);
        Ok(exec_steps)
    }
}

fn gen_codecopy_step(
    state: &mut CircuitInputStateRef,
    geth_step: &GethExecStep,
) -> Result<ExecStep, Error> {
    let mut exec_step = state.new_step(geth_step)?;

    let length = geth_step.stack.nth_last(0)?;
    let code_offset = geth_step.stack.nth_last(1)?;
    let dest_offset = geth_step.stack.nth_last(2)?;

    // stack reads
    state.stack_read(
        &mut exec_step,
        geth_step.stack.nth_last_filled(0),
        dest_offset,
    )?;
    state.stack_read(
        &mut exec_step,
        geth_step.stack.nth_last_filled(1),
        code_offset,
    )?;
    state.stack_read(&mut exec_step, geth_step.stack.nth_last_filled(2), length)?;

    Ok(exec_step)
}

fn gen_copy_steps(
    state: &mut CircuitInputStateRef,
    exec_step: &mut ExecStep,
    src_addr: u64,
    dst_addr: u64,
    bytes_left: u64,
    bytecode: &Bytecode,
) -> Result<Vec<(u8, bool)>, Error> {
    let mut steps = Vec::with_capacity(bytes_left as usize);
    for idx in 0..bytes_left {
        let addr = src_addr + idx;
        let bytecode_element = bytecode.get(addr as usize).unwrap_or_default();
        steps.push((bytecode_element.value, bytecode_element.is_code));
        state.memory_write(exec_step, (dst_addr + idx).into(), bytecode_element.value)?;
    }
    Ok(steps)
}

fn gen_copy_event(
    state: &mut CircuitInputStateRef,
    geth_step: &GethExecStep,
) -> Result<CopyEvent, Error> {
    let rw_counter_start = state.block_ctx.rwc;

    let length = geth_step.stack.nth_last(0)?.as_u64();
    let code_offset = geth_step.stack.nth_last(1)?.as_u64();
    let dest_offset = geth_step.stack.nth_last(2)?.as_u64();

    let code_hash = state.call()?.code_hash;
    let bytecode_bytes = state.code(code_hash)?;
    // TODO check if replacement of [Bytecode::from] -> [Bytecode::from_raw_unchecked] is correct
    let bytecode= Bytecode::from_raw_unchecked(bytecode_bytes);
    let src_addr_end = bytecode.to_vec().len() as u64;

    let mut exec_step = state.new_step(geth_step)?;
    let copy_steps = gen_copy_steps(
        state,
        &mut exec_step,
        code_offset,
        dest_offset,
        length,
        &bytecode,
    )?;

    Ok(CopyEvent {
        src_type: CopyDataType::Bytecode,
        src_id: NumberOrHash::Hash(code_hash),
        src_addr: code_offset,
        src_addr_end,
        dst_type: CopyDataType::Memory,
        dst_id: NumberOrHash::Number(state.call()?.call_id),
        dst_addr: dest_offset,
        log_id: None,
        rw_counter_start,
        bytes: copy_steps,
    })
}

#[cfg(test)]
mod codecopy_tests {
    use eth_types::{bytecode, Bytecode, evm_types::{MemoryAddress, OpcodeId, StackAddress}, geth_types::GethData, H256, StackWord};
    use ethers_core::utils::keccak256;
    use eth_types::bytecode::WasmBinaryBytecode;
    use mock::{
        test_ctx::helpers::{account_0_code_account_1_no_code, tx_from_1_to_0},
        TestContext,
    };

    use crate::{
        circuit_input_builder::{CopyDataType, ExecState, NumberOrHash},
        mocks::BlockData,
        operation::{MemoryOp, StackOp, RW},
    };

    #[test]
    fn codecopy_opcode_impl1() {
        test_ok(0x00, 0x00, 0x40);
    }

    #[test]
    fn codecopy_opcode_impl2() {
        test_ok(0x20, 0x40, 0x14);
    }

    fn test_ok(dest_offset: usize, code_offset: usize, size: usize) {
        let code = bytecode! {
            I32Const[dest_offset]
            I32Const[code_offset]
            I32Const[size]
            CODECOPY
        };

        let block: GethData = TestContext::<2, 1>::new(
            None,
            account_0_code_account_1_no_code(code.clone()),
            tx_from_1_to_0,
            |block, _tx| block.number(0xcafeu64),
        )
        .unwrap()
        .into();

        let wasm_binary_vec = code.wasm_binary();
        let code = Bytecode::from_raw_unchecked(code.wasm_binary());

        let mut builder = BlockData::new_from_geth_data(block.clone()).new_circuit_input_builder();
        builder
            .handle_block(&block.eth_block, &block.geth_traces)
            .unwrap();

        let step = builder.block.txs()[0]
            .steps()
            .iter()
            .find(|step| step.exec_state == ExecState::Op(OpcodeId::CODECOPY))
            .unwrap();

        let expected_call_id = builder.block.txs()[0].calls()[step.call_index].call_id;

        assert_eq!(
            [0, 1, 2]
                .map(|idx| &builder.block.container.stack[step.bus_mapping_instance[idx].as_usize()])
                .map(|op| (op.rw(), op.op())),
            [
                (
                    RW::READ,
                    &StackOp::new(expected_call_id, StackAddress::from(1021), StackWord::from(dest_offset)),
                ),
                (
                    RW::READ,
                    &StackOp::new(expected_call_id, StackAddress::from(1022), StackWord::from(code_offset)),
                ),
                (
                    RW::READ,
                    &StackOp::new(expected_call_id, StackAddress::from(1023), StackWord::from(size)),
                ),
            ]
        );

        // RW table memory writes.
        for idx in 0..size {
            let op = &builder.block.container.memory[idx];

            let op_rw_expected = RW::WRITE;
            let op_expected = MemoryOp::new(
                expected_call_id,
                MemoryAddress::from(dest_offset + idx),
                if code_offset + idx < code.to_vec().len() {
                    wasm_binary_vec[code_offset + idx]
                } else {
                    0
                },
            );
            assert_eq!(op.rw(), op_rw_expected, "op.rw() at idx {}", idx);
            assert_eq!(op.op().clone(), op_expected, "op.op() at idx {}", idx);
        }

        let copy_events = builder.block.copy_events.clone();
        assert_eq!(copy_events.len(), 1);
        assert_eq!(copy_events[0].bytes.len(), size);
        assert_eq!(
            copy_events[0].src_id,
            NumberOrHash::Hash(H256(keccak256(&wasm_binary_vec)))
        );
        assert_eq!(copy_events[0].src_addr as usize, code_offset);
        assert_eq!(copy_events[0].src_addr_end as usize, code.to_vec().len());
        assert_eq!(copy_events[0].src_type, CopyDataType::Bytecode);
        assert_eq!(
            copy_events[0].dst_id,
            NumberOrHash::Number(expected_call_id)
        );
        assert_eq!(copy_events[0].dst_addr as usize, dest_offset);
        assert_eq!(copy_events[0].dst_type, CopyDataType::Memory);
        assert!(copy_events[0].log_id.is_none());

        for (idx, (value, is_code)) in copy_events[0].bytes.iter().enumerate() {
            let bytecode_element = code.get(code_offset + idx).unwrap_or_default();
            assert_eq!(*value, bytecode_element.value);
            assert_eq!(*is_code, bytecode_element.is_code);
        }
    }
}
