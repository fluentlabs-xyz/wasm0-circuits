use super::{Opcode, OpcodeId};
use crate::{
    circuit_input_builder::{CircuitInputStateRef, ExecStep},
    error::{ExecError, OogError},
    operation::{CallContextField, StorageOp, TxAccessListAccountStorageOp, RW},
    Error,
};
use eth_types::{GethExecStep, ToBigEndian, ToLittleEndian, ToU256, ToWord};
use eth_types::evm_types::MemoryAddress;

/// Placeholder structure used to implement [`Opcode`] trait over it
/// corresponding to the
/// [`OogError::SloadSstore`](crate::error::OogError::SloadSstore).
#[derive(Clone, Copy, Debug)]
pub(crate) struct OOGSloadSstore;

impl Opcode for OOGSloadSstore {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        geth_steps: &[GethExecStep],
    ) -> Result<Vec<ExecStep>, Error> {
        let geth_step = &geth_steps[0];
        debug_assert!([OpcodeId::SLOAD, OpcodeId::SSTORE].contains(&geth_step.op));

        let mut exec_step = state.new_step(geth_step)?;
        exec_step.error = Some(ExecError::OutOfGas(OogError::SloadSstore));

        let call_id = state.call()?.call_id;
        let callee_address = state.call()?.address;
        let tx_id = state.tx_ctx.id();

        state.call_context_read(
            &mut exec_step,
            call_id,
            CallContextField::TxId,
            tx_id.into(),
        );

        state.call_context_read(
            &mut exec_step,
            call_id,
            CallContextField::IsStatic,
            (state.call()?.is_static as u8).into(),
        );

        state.call_context_read(
            &mut exec_step,
            call_id,
            CallContextField::CalleeAddress,
            callee_address.to_word(),
        );

        // First stack read
        let value_offset = geth_step.stack.nth_last(0)?;
        let key_offset = geth_step.stack.nth_last(1)?;

        // Manage first stack read at latest stack position
        state.stack_read(&mut exec_step, geth_step.stack.nth_last_filled(0), value_offset)?;
        state.stack_read(&mut exec_step, geth_step.stack.nth_last_filled(1), key_offset)?;

        let key = geth_step.global_memory.read_u256(key_offset)?;
        let key_bytes = key.to_be_bytes();

        // Storage read
        let value = geth_step.global_memory.read_u256(value_offset)?;
        let value_bytes = value.to_be_bytes();

        state.memory_read_n(&mut exec_step, MemoryAddress::from(key_offset.as_u64()), &key_bytes)?;
        state.memory_write_n(&mut exec_step, MemoryAddress::from(value_offset.as_u64()), &value_bytes)?;

        let is_warm = state
            .sdb
            .check_account_storage_in_access_list(&(callee_address, key.to_u256()));
        state.push_op(
            &mut exec_step,
            RW::READ,
            TxAccessListAccountStorageOp {
                tx_id,
                address: callee_address,
                key: key.to_u256(),
                is_warm,
                is_warm_prev: is_warm,
            },
        );

        // Special operations are only used for SSTORE.
        if geth_step.op == OpcodeId::SSTORE {
            let (_, value_prev) = state.sdb.get_storage(&callee_address, &key.to_u256());
            let (_, original_value) = state.sdb.get_committed_storage(&callee_address, &key.to_u256());

            state.push_op(
                &mut exec_step,
                RW::READ,
                StorageOp::new(
                    callee_address,
                    key.to_u256(),
                    *value_prev,
                    *value_prev,
                    tx_id,
                    *original_value,
                ),
            );
        }

        state.handle_return(&mut exec_step, geth_steps, true)?;
        Ok(vec![exec_step])
    }
}
