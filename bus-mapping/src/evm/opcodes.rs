//! Definition of each opcode of the EVM.
use crate::{
    circuit_input_builder::{CircuitInputStateRef, ExecStep},
    error::{ExecError, OogError},
    Error,
    evm::OpcodeId,
    operation::{
        AccountField, AccountOp, CallContextField, RW, TxAccessListAccountOp, TxReceiptField,
        TxRefundOp,
    },
};
use core::fmt::Debug;
use eth_types::{evm_types::{GasCost, MAX_REFUND_QUOTIENT_OF_GAS_USED}, evm_unimplemented, GethExecStep, GethExecTrace, StackWord, ToAddress, ToWord, Word};
use ethers_core::utils::get_contract_address;
use keccak256::EMPTY_HASH;

#[cfg(any(feature = "test", test))]
pub use self::sha3::sha3_tests::{gen_sha3_code, MemoryKind};

mod address;
mod balance;
mod calldatacopy;
mod calldataload;
mod calldatasize;
mod caller;
mod callop;
mod callvalue;
mod chainid;
mod codecopy;
mod codesize;
// mod create;
// mod dup;
// mod exp;
// mod extcodecopy;
// mod extcodehash;
mod extcodesize;
mod gasprice;
// mod logs;
// mod mload;
// mod mstore;
mod number;
mod origin;
mod return_revert;
mod returndatacopy;
mod returndatasize;
mod selfbalance;
mod sha3;
// mod sload;
// mod sstore;
mod stackonlyop;
mod stacktomemoryop;
mod stop;
// mod swap;

mod error_invalid_jump;
mod error_oog_call;
mod error_oog_exp;
mod error_oog_log;
mod error_oog_sload_sstore;
mod error_return_data_outofbound;
mod error_simple;
mod error_write_protection;

#[cfg(test)]
mod memory_expansion_test;
mod wasm_global;

use address::Address;
use balance::Balance;
use calldatacopy::Calldatacopy;
use calldataload::Calldataload;
use calldatasize::Calldatasize;
use caller::Caller;
use callop::CallOpcode;
use callvalue::Callvalue;
use codecopy::Codecopy;
use codesize::Codesize;
use error_invalid_jump::InvalidJump;
use error_oog_call::OOGCall;
use error_oog_exp::OOGExp;
use error_oog_log::ErrorOOGLog;
use error_oog_sload_sstore::OOGSloadSstore;
use error_return_data_outofbound::ErrorReturnDataOutOfBound;
use error_simple::ErrorSimple;
use error_write_protection::ErrorWriteProtection;
use eth_types::evm_types::{MemoryAddress};
use gasprice::GasPrice;
use origin::Origin;
use return_revert::ReturnRevert;
use returndatacopy::Returndatacopy;
use returndatasize::Returndatasize;
use selfbalance::Selfbalance;
use stackonlyop::StackOnlyOpcode;
use stop::Stop;
use crate::evm::opcodes::chainid::ChainId;
use crate::evm::opcodes::extcodesize::Extcodesize;
use crate::evm::opcodes::wasm_global::WasmGlobalOpcode;
use crate::evm::opcodes::number::Number;
use crate::evm::opcodes::stacktomemoryop::StackToMemoryOpcode;

/// Generic opcode trait which defines the logic of the
/// [`Operation`](crate::operation::Operation) that should be generated for one
/// or multiple [`ExecStep`](crate::circuit_input_builder::ExecStep) depending
/// of the [`OpcodeId`] it contains.
pub trait Opcode: Debug {
    /// Generate the associated [`MemoryOp`](crate::operation::MemoryOp)s,
    /// [`StackOp`](crate::operation::StackOp)s, and
    /// [`StorageOp`](crate::operation::StorageOp)s associated to the Opcode
    /// is implemented for.
    fn gen_associated_ops(
        _state: &mut CircuitInputStateRef,
        _geth_steps: &[GethExecStep],
    ) -> Result<Vec<ExecStep>, Error>;
}

#[derive(Debug, Copy, Clone)]
struct Dummy;

impl Opcode for Dummy {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        geth_steps: &[GethExecStep],
    ) -> Result<Vec<ExecStep>, Error> {
        Ok(vec![state.new_step(&geth_steps[0])?])
    }
}

type FnGenAssociatedOps = fn(
    state: &mut CircuitInputStateRef,
    geth_steps: &[GethExecStep],
) -> Result<Vec<ExecStep>, Error>;

fn fn_gen_associated_ops(opcode_id: &OpcodeId) -> FnGenAssociatedOps {
    match opcode_id {
        // WASM opcodes
        OpcodeId::Unreachable => Stop::gen_associated_ops,
        // OpcodeId::Nop => Dummy::gen_associated_ops,
        // OpcodeId::Block => Dummy::gen_associated_ops,
        // OpcodeId::Loop => Dummy::gen_associated_ops,
        // OpcodeId::If => Dummy::gen_associated_ops,
        // OpcodeId::Else => Dummy::gen_associated_ops,
        OpcodeId::End => Stop::gen_associated_ops,
        // OpcodeId::Br => Dummy::gen_associated_ops,
        // OpcodeId::BrIf => Dummy::gen_associated_ops,
        // OpcodeId::BrTable => Dummy::gen_associated_ops,
        // OpcodeId::Return => Dummy::gen_associated_ops,
        // OpcodeId::Call => Dummy::gen_associated_ops,
        // OpcodeId::CallIndirect => Dummy::gen_associated_ops,
        // OpcodeId::Drop => Dummy::gen_associated_ops,
        // OpcodeId::Select => Dummy::gen_associated_ops,
        // OpcodeId::GetLocal => Dummy::gen_associated_ops,
        // OpcodeId::SetLocal => Dummy::gen_associated_ops,
        // OpcodeId::TeeLocal => Dummy::gen_associated_ops,
        // OpcodeId::GetGlobal => Dummy::gen_associated_ops,
        // OpcodeId::SetGlobal => Dummy::gen_associated_ops,
        // OpcodeId::I32Load => Dummy::gen_associated_ops,
        // OpcodeId::I64Load => Dummy::gen_associated_ops,
        // OpcodeId::F32Load => Dummy::gen_associated_ops,
        // OpcodeId::F64Load => Dummy::gen_associated_ops,
        // OpcodeId::I32Load8S => Dummy::gen_associated_ops,
        // OpcodeId::I32Load8U => Dummy::gen_associated_ops,
        // OpcodeId::I32Load16S => Dummy::gen_associated_ops,
        // OpcodeId::I32Load16U => Dummy::gen_associated_ops,
        // OpcodeId::I64Load8S => Dummy::gen_associated_ops,
        // OpcodeId::I64Load8U => Dummy::gen_associated_ops,
        // OpcodeId::I64Load16S => Dummy::gen_associated_ops,
        // OpcodeId::I64Load16U => Dummy::gen_associated_ops,
        // OpcodeId::I64Load32S => Dummy::gen_associated_ops,
        // OpcodeId::I64Load32U => Dummy::gen_associated_ops,
        // OpcodeId::I32Store => Dummy::gen_associated_ops,
        // OpcodeId::I64Store => Dummy::gen_associated_ops,
        // OpcodeId::F32Store => Dummy::gen_associated_ops,
        // OpcodeId::F64Store => Dummy::gen_associated_ops,
        // OpcodeId::I32Store8 => Dummy::gen_associated_ops,
        // OpcodeId::I32Store16 => Dummy::gen_associated_ops,
        // OpcodeId::I64Store8 => Dummy::gen_associated_ops,
        // OpcodeId::I64Store16 => Dummy::gen_associated_ops,
        // OpcodeId::I64Store32 => Dummy::gen_associated_ops,
        // OpcodeId::CurrentMemory => Dummy::gen_associated_ops,
        // OpcodeId::GrowMemory => Dummy::gen_associated_ops,
        OpcodeId::I32Const |
        OpcodeId::I64Const => StackOnlyOpcode::<0, 1>::gen_associated_ops,
        // WASM binary opcodes
        OpcodeId::I32Add |
        OpcodeId::I32Sub |
        OpcodeId::I32Mul |
        OpcodeId::I32DivS |
        OpcodeId::I32DivU |
        OpcodeId::I32RemS |
        OpcodeId::I32RemU |
        OpcodeId::I32And |
        OpcodeId::I32Or |
        OpcodeId::I32Xor |
        OpcodeId::I32Shl |
        OpcodeId::I32ShrS |
        OpcodeId::I32ShrU |
        OpcodeId::I32Rotl |
        OpcodeId::I32Rotr |
        OpcodeId::I64Add |
        OpcodeId::I64Sub |
        OpcodeId::I64Mul |
        OpcodeId::I64DivS |
        OpcodeId::I64DivU |
        OpcodeId::I64RemS |
        OpcodeId::I64RemU |
        OpcodeId::I64And |
        OpcodeId::I64Or |
        OpcodeId::I64Xor |
        OpcodeId::I64Shl |
        OpcodeId::I64ShrS |
        OpcodeId::I64ShrU |
        OpcodeId::I64Rotl |
        OpcodeId::I64Rotr => StackOnlyOpcode::<2, 1>::gen_associated_ops,
        // WASM unary opcodes
        OpcodeId::I32Ctz |
        OpcodeId::I64Ctz |
        OpcodeId::I32Clz |
        OpcodeId::I64Clz |
        OpcodeId::I32Popcnt |
        OpcodeId::I64Popcnt => StackOnlyOpcode::<1, 1>::gen_associated_ops,
        // WASM global opcodes
        OpcodeId::SetGlobal |
        OpcodeId::GetGlobal => WasmGlobalOpcode::gen_associated_ops,

        OpcodeId::Drop => StackOnlyOpcode::<1, 0>::gen_associated_ops,
        OpcodeId::Return => Dummy::gen_associated_ops,

        // TODO these are temporal. need a fix.
        // OpcodeId::GetLocal => Dummy::gen_associated_ops,
        // OpcodeId::SetLocal => Dummy::gen_associated_ops,
        // OpcodeId::I32GtU => Dummy::gen_associated_ops,
        // OpcodeId::If => Dummy::gen_associated_ops,
        // OpcodeId::Call => Dummy::gen_associated_ops,

        // EVM opcodes
        OpcodeId::STOP => Stop::gen_associated_ops,
        // OpcodeId::SHA3 => Sha3::gen_associated_ops,
        OpcodeId::ADDRESS => Address::gen_associated_ops,
        OpcodeId::BALANCE => Balance::gen_associated_ops,
        OpcodeId::ORIGIN => Origin::gen_associated_ops,
        OpcodeId::CALLER => Caller::gen_associated_ops,
        OpcodeId::CALLVALUE => Callvalue::gen_associated_ops,
        OpcodeId::CALLDATASIZE => Calldatasize::gen_associated_ops,
        OpcodeId::CALLDATALOAD => Calldataload::gen_associated_ops,
        OpcodeId::CALLDATACOPY => Calldatacopy::gen_associated_ops,
        OpcodeId::GASPRICE => GasPrice::gen_associated_ops,
        OpcodeId::CODECOPY => Codecopy::gen_associated_ops,
        OpcodeId::CODESIZE => Codesize::gen_associated_ops,
        OpcodeId::EXTCODESIZE => Extcodesize::gen_associated_ops,
        // OpcodeId::EXTCODECOPY => Extcodecopy::gen_associated_ops,
        OpcodeId::RETURNDATASIZE => Returndatasize::gen_associated_ops,
        OpcodeId::RETURNDATACOPY => Returndatacopy::gen_associated_ops,
        // OpcodeId::EXTCODEHASH => Extcodehash::gen_associated_ops,
        OpcodeId::BLOCKHASH => StackOnlyOpcode::<1, 1>::gen_associated_ops,
        OpcodeId::COINBASE => StackOnlyOpcode::<0, 1>::gen_associated_ops,
        OpcodeId::TIMESTAMP => StackOnlyOpcode::<0, 1>::gen_associated_ops,
        // OpcodeId::NUMBER => StackOnlyOpcode::<0, 1>::gen_associated_ops,
        OpcodeId::NUMBER => Number::gen_associated_ops,
        OpcodeId::DIFFICULTY => StackToMemoryOpcode::gen_associated_ops,
        OpcodeId::GASLIMIT => StackToMemoryOpcode::gen_associated_ops,
        OpcodeId::CHAINID => ChainId::gen_associated_ops,
        OpcodeId::SELFBALANCE => Selfbalance::gen_associated_ops,
        OpcodeId::BASEFEE => StackToMemoryOpcode::gen_associated_ops,
        // OpcodeId::MLOAD => Mload::gen_associated_ops,
        // OpcodeId::MSTORE => Mstore::<false>::gen_associated_ops,
        // OpcodeId::MSTORE8 => Mstore::<true>::gen_associated_ops,
        // OpcodeId::SLOAD => Sload::gen_associated_ops,
        // OpcodeId::SSTORE => Sstore::gen_associated_ops,
        OpcodeId::PC => StackOnlyOpcode::<0, 1>::gen_associated_ops,
        OpcodeId::MSIZE => StackOnlyOpcode::<0, 1>::gen_associated_ops,
        OpcodeId::GAS => StackOnlyOpcode::<0, 1>::gen_associated_ops,
        OpcodeId::JUMPDEST => Dummy::gen_associated_ops,
        // OpcodeId::LOG0 => Log::gen_associated_ops,
        // OpcodeId::LOG1 => Log::gen_associated_ops,
        // OpcodeId::LOG2 => Log::gen_associated_ops,
        // OpcodeId::LOG3 => Log::gen_associated_ops,
        // OpcodeId::LOG4 => Log::gen_associated_ops,
        OpcodeId::CALL | OpcodeId::CALLCODE => CallOpcode::<true>::gen_associated_ops,
        OpcodeId::DELEGATECALL | OpcodeId::STATICCALL => CallOpcode::<false>::gen_associated_ops,
        OpcodeId::RETURN | OpcodeId::REVERT => ReturnRevert::gen_associated_ops,
        OpcodeId::SELFDESTRUCT => {
            evm_unimplemented!("Using dummy gen_selfdestruct_ops for opcode SELFDESTRUCT");
            DummySelfDestruct::gen_associated_ops
        }
        // OpcodeId::CREATE => {
        //     evm_unimplemented!("Using dummy gen_create_ops for opcode {:?}", opcode_id);
        //     DummyCreate::<false>::gen_associated_ops
        // }
        // OpcodeId::CREATE2 => {
        //     evm_unimplemented!("Using dummy gen_create_ops for opcode {:?}", opcode_id);
        //     DummyCreate::<true>::gen_associated_ops
        // }
        _ => {
            evm_unimplemented!("Using dummy gen_associated_ops for opcode {:?}", opcode_id);
            Dummy::gen_associated_ops
        }
    }
}

fn fn_gen_error_state_associated_ops(error: &ExecError) -> Option<FnGenAssociatedOps> {
    match error {
        ExecError::InvalidJump => Some(InvalidJump::gen_associated_ops),
        ExecError::InvalidOpcode => Some(ErrorSimple::gen_associated_ops),
        ExecError::OutOfGas(OogError::Call) => Some(OOGCall::gen_associated_ops),
        ExecError::OutOfGas(OogError::Constant) => Some(ErrorSimple::gen_associated_ops),
        ExecError::OutOfGas(OogError::Exp) => Some(OOGExp::gen_associated_ops),
        ExecError::OutOfGas(OogError::Log) => Some(ErrorOOGLog::gen_associated_ops),
        ExecError::OutOfGas(OogError::SloadSstore) => Some(OOGSloadSstore::gen_associated_ops),
        ExecError::StackOverflow => Some(ErrorSimple::gen_associated_ops),
        ExecError::StackUnderflow => Some(ErrorSimple::gen_associated_ops),
        // call & callcode can encounter InsufficientBalance error, Use pop-7 generic CallOpcode
        ExecError::InsufficientBalance => Some(CallOpcode::<true>::gen_associated_ops),
        ExecError::WriteProtection => Some(ErrorWriteProtection::gen_associated_ops),
        ExecError::ReturnDataOutOfBounds => Some(ErrorReturnDataOutOfBound::gen_associated_ops),
        // more future errors place here
        _ => {
            evm_unimplemented!("TODO: error state {:?} not implemented", error);
            None
        }
    }
}

#[allow(clippy::collapsible_else_if)]
/// Generate the associated operations according to the particular
/// [`OpcodeId`].
pub fn gen_associated_ops(
    opcode_id: &OpcodeId,
    state: &mut CircuitInputStateRef,
    geth_steps: &[GethExecStep],
) -> Result<Vec<ExecStep>, Error> {

    // check if have error
    let geth_step = &geth_steps[0];
    let mut exec_step = state.new_step(geth_step)?;
    let next_step = if geth_steps.len() > 1 {
        Some(&geth_steps[1])
    } else {
        None
    };
    if let Some(exec_error) = state.get_step_err(geth_step, next_step).unwrap() {
        log::warn!(
            "geth error {:?} occurred in  {:?} at pc {:?}",
            exec_error,
            geth_step.op,
            geth_step.pc,
        );

        exec_step.error = Some(exec_error.clone());
        // TODO: after more error state handled, refactor all error handling in
        // fn_gen_error_state_associated_ops method
        // For exceptions that have been implemented
        if let Some(fn_gen_error_ops) = fn_gen_error_state_associated_ops(&exec_error) {
            return fn_gen_error_ops(state, geth_steps);
        } else {
            // For exceptions that already enter next call context, but fail immediately
            // (e.g. Depth, InsufficientBalance), we still need to parse the call.
            if geth_step.op.is_call_or_create() {
                let call = state.parse_call(geth_step)?;
                state.push_call(call);
                // For exceptions that fail to enter next call context, we need
                // to restore call context of current caller
            } else {
                state.gen_restore_context_ops(&mut exec_step, geth_steps)?;
            }
            state.handle_return(geth_step)?;
            return Ok(vec![exec_step]);
        }
    }
    // if no errors, continue as normal
    let fn_gen_associated_ops = fn_gen_associated_ops(opcode_id);
    fn_gen_associated_ops(state, geth_steps)
}

pub fn gen_begin_tx_ops(state: &mut CircuitInputStateRef, exec_trace: &GethExecTrace) -> Result<ExecStep, Error> {
    let mut exec_step = state.new_begin_tx_step();
    let call = state.call()?.clone();

    for (field, value) in [
        (CallContextField::TxId, state.tx_ctx.id().into()),
        (
            CallContextField::RwCounterEndOfReversion,
            call.rw_counter_end_of_reversion.into(),
        ),
        (
            CallContextField::IsPersistent,
            (call.is_persistent as usize).into(),
        ),
        (CallContextField::IsSuccess, call.is_success.to_word()),
    ] {
        state.call_context_write(&mut exec_step, call.call_id, field, value);
    }

    // Increase caller's nonce
    let caller_address = call.caller_address;
    let nonce_prev = state.sdb.get_account(&caller_address).1.nonce;
    state.account_write(
        &mut exec_step,
        caller_address,
        AccountField::Nonce,
        nonce_prev + 1,
        nonce_prev,
    )?;

    // Add caller and callee into access list
    for address in [call.caller_address, call.address] {
        let is_warm_prev = !state.sdb.add_account_to_access_list(address);
        state.tx_accesslist_account_write(
            &mut exec_step,
            state.tx_ctx.id(),
            address,
            true,
            is_warm_prev,
        )?;
    }

    // Calculate intrinsic gas cost
    let call_data_gas_cost = state
        .tx
        .input
        .iter()
        .fold(0, |acc, byte| acc + if *byte == 0 { 4 } else { 16 });
    let intrinsic_gas_cost = if state.tx.is_create() {
        GasCost::CREATION_TX.as_u64()
    } else {
        GasCost::TX.as_u64()
    } + call_data_gas_cost;
    exec_step.gas_cost = GasCost(intrinsic_gas_cost);

    // Transfer with fee
    state.transfer_with_fee(
        &mut exec_step,
        call.caller_address,
        call.address,
        call.value,
        Some(state.tx.gas_price * state.tx.gas),
    )?;

    // Get code_hash of callee
    let (_, callee_account) = state.sdb.get_account(&call.address);
    let callee_exists = !callee_account.is_empty();
    let (callee_code_hash, is_empty_code_hash) = if callee_exists {
        (
            call.code_hash.to_word(),
            call.code_hash.to_fixed_bytes() == *EMPTY_HASH,
        )
    } else {
        (Word::zero(), true)
    };

    // In case of contract creation we wish to verify the correctness of the
    // contract's address (callee). This address is defined as:
    //
    // Keccak256(RLP([tx_caller, tx_nonce]))[12:]
    //
    // We feed the RLP-encoded bytes to the block's SHA3 inputs, which gets assigned
    // to the Keccak circuit, so that the BeginTxGadget can do a lookup to the
    // Keccak table and verify the contract address.
    if state.tx.is_create() {
        state.block.sha3_inputs.push({
            let mut stream = ethers_core::utils::rlp::RlpStream::new();
            stream.begin_list(2);
            stream.append(&caller_address);
            stream.append(&nonce_prev);
            stream.out().to_vec()
        });
    }

    // There are 4 branches from here.
    match (
        call.is_create(),
        state.is_precompiled(&call.address),
        is_empty_code_hash,
    ) {
        // 1. Creation transaction.
        (true, _, _) => {
            state.push_op_reversible(
                &mut exec_step,
                RW::WRITE,
                AccountOp {
                    address: call.address,
                    field: AccountField::Nonce,
                    value: 1.into(),
                    value_prev: 0.into(),
                },
            )?;
            for (field, value) in [
                (CallContextField::Depth, call.depth.into()),
                (
                    CallContextField::CallerAddress,
                    call.caller_address.to_word(),
                ),
                (
                    CallContextField::CalleeAddress,
                    get_contract_address(caller_address, nonce_prev).to_word(),
                ),
                (
                    CallContextField::CallDataOffset,
                    call.call_data_offset.into(),
                ),
                (
                    CallContextField::CallDataLength,
                    state.tx.input.len().into(),
                ),
                (CallContextField::Value, call.value),
                (CallContextField::IsStatic, (call.is_static as usize).into()),
                (CallContextField::LastCalleeId, 0.into()),
                (CallContextField::LastCalleeReturnDataOffset, 0.into()),
                (CallContextField::LastCalleeReturnDataLength, 0.into()),
                (CallContextField::IsRoot, 1.into()),
                (CallContextField::IsCreate, 1.into()),
                (CallContextField::CodeHash, call.code_hash.to_word()),
            ] {
                state.call_context_write(&mut exec_step, call.call_id, field, value);
            }
        }
        // 2. Call to precompiled.
        (_, true, _) => {
            evm_unimplemented!("Call to precompiled is left unimplemented");
        }
        (_, _, is_empty_code_hash) => {
            state.account_read(
                &mut exec_step,
                call.address,
                AccountField::CodeHash,
                callee_code_hash,
                callee_code_hash,
            );

            // 3. Call to account with empty code.
            if !is_empty_code_hash {

                // 4. Call to account with non-empty code.
                for (field, value) in [
                    (CallContextField::Depth, call.depth.into()),
                    (
                        CallContextField::CallerAddress,
                        call.caller_address.to_word(),
                    ),
                    (CallContextField::CalleeAddress, call.address.to_word()),
                    (
                        CallContextField::CallDataOffset,
                        call.call_data_offset.into(),
                    ),
                    (
                        CallContextField::CallDataLength,
                        call.call_data_length.into(),
                    ),
                    (CallContextField::Value, call.value),
                    (CallContextField::IsStatic, (call.is_static as usize).into()),
                    (CallContextField::LastCalleeId, 0.into()),
                    (CallContextField::LastCalleeReturnDataOffset, 0.into()),
                    (CallContextField::LastCalleeReturnDataLength, 0.into()),
                    (CallContextField::IsRoot, 1.into()),
                    (CallContextField::IsCreate, 0.into()),
                    (CallContextField::CodeHash, callee_code_hash),
                ] {
                    state.call_context_write(&mut exec_step, call.call_id, field, value);
                }
            }
        }
    };

    // Initialize WASM global memory and global variables section
    for (i, byte) in exec_trace.global_memory.0.iter().enumerate() {
        if *byte != 0 {
            state.memory_write(&mut exec_step, MemoryAddress::from(i), *byte)?;
        }
    }
    for global in &exec_trace.globals {
        // TODO: "proof const evaluation"
        state.global_write(&mut exec_step, global.index, StackWord::from(global.value))?;
    }

    Ok(exec_step)
}

pub fn gen_end_tx_ops(state: &mut CircuitInputStateRef) -> Result<ExecStep, Error> {
    let mut exec_step = state.new_end_tx_step();
    let call = state.tx.calls()[0].clone();

    state.call_context_read(
        &mut exec_step,
        call.call_id,
        CallContextField::TxId,
        state.tx_ctx.id().into(),
    );
    state.call_context_read(
        &mut exec_step,
        call.call_id,
        CallContextField::IsPersistent,
        Word::from(call.is_persistent as u8),
    );

    let refund = state.sdb.refund();
    state.push_op(
        &mut exec_step,
        RW::READ,
        TxRefundOp {
            tx_id: state.tx_ctx.id(),
            value: refund,
            value_prev: refund,
        },
    );

    let effective_refund =
        refund.min((state.tx.gas - exec_step.gas_left.0) / MAX_REFUND_QUOTIENT_OF_GAS_USED as u64);
    let (found, caller_account) = state.sdb.get_account(&call.caller_address);
    if !found {
        return Err(Error::AccountNotFound(call.caller_address));
    }
    let caller_balance_prev = caller_account.balance;
    let caller_balance =
        caller_balance_prev + state.tx.gas_price * (exec_step.gas_left.0 + effective_refund);
    state.account_write(
        &mut exec_step,
        call.caller_address,
        AccountField::Balance,
        caller_balance,
        caller_balance_prev,
    )?;

    let effective_tip = state.tx.gas_price - state.block.base_fee;
    let (found, coinbase_account) = state.sdb.get_account(&state.block.coinbase);
    if !found {
        return Err(Error::AccountNotFound(state.block.coinbase));
    }
    let coinbase_balance_prev = coinbase_account.balance;
    let coinbase_balance =
        coinbase_balance_prev + effective_tip * (state.tx.gas - exec_step.gas_left.0);
    state.account_write(
        &mut exec_step,
        state.block.coinbase,
        AccountField::Balance,
        coinbase_balance,
        coinbase_balance_prev,
    )?;

    // handle tx receipt tag
    state.tx_receipt_write(
        &mut exec_step,
        state.tx_ctx.id(),
        TxReceiptField::PostStateOrStatus,
        call.is_persistent as u64,
    )?;

    let log_id = exec_step.log_id;
    state.tx_receipt_write(
        &mut exec_step,
        state.tx_ctx.id(),
        TxReceiptField::LogLength,
        log_id as u64,
    )?;

    if state.tx_ctx.id() > 1 {
        // query pre tx cumulative gas
        state.tx_receipt_read(
            &mut exec_step,
            state.tx_ctx.id() - 1,
            TxReceiptField::CumulativeGasUsed,
            state.block_ctx.cumulative_gas_used,
        )?;
    }

    state.block_ctx.cumulative_gas_used += state.tx.gas - exec_step.gas_left.0;
    state.tx_receipt_write(
        &mut exec_step,
        state.tx_ctx.id(),
        TxReceiptField::CumulativeGasUsed,
        state.block_ctx.cumulative_gas_used,
    )?;

    if !state.tx_ctx.is_last_tx() {
        state.call_context_write(
            &mut exec_step,
            state.block_ctx.rwc.0 + 1,
            CallContextField::TxId,
            (state.tx_ctx.id() + 1).into(),
        );
    }

    Ok(exec_step)
}

#[derive(Debug, Copy, Clone)]
struct DummySelfDestruct;

impl Opcode for DummySelfDestruct {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        geth_steps: &[GethExecStep],
    ) -> Result<Vec<ExecStep>, Error> {
        dummy_gen_selfdestruct_ops(state, geth_steps)
    }
}

fn dummy_gen_selfdestruct_ops(
    state: &mut CircuitInputStateRef,
    geth_steps: &[GethExecStep],
) -> Result<Vec<ExecStep>, Error> {
    let geth_step = &geth_steps[0];
    let mut exec_step = state.new_step(geth_step)?;
    let sender = state.call()?.address;
    let receiver = geth_step.stack.last()?.to_address();

    let is_warm = state.sdb.check_account_in_access_list(&receiver);
    state.push_op_reversible(
        &mut exec_step,
        RW::WRITE,
        TxAccessListAccountOp {
            tx_id: state.tx_ctx.id(),
            address: receiver,
            is_warm: true,
            is_warm_prev: is_warm,
        },
    )?;

    let (found, _) = state.sdb.get_account(&receiver);
    if !found {
        return Err(Error::AccountNotFound(receiver));
    }
    let (found, sender_account) = state.sdb.get_account(&sender);
    if !found {
        return Err(Error::AccountNotFound(sender));
    }
    let value = sender_account.balance;
    state.transfer(&mut exec_step, sender, receiver, value)?;

    if state.call()?.is_persistent {
        state.sdb.destruct_account(sender);
    }

    state.handle_return(geth_step)?;
    Ok(vec![exec_step])
}

pub fn append_vector_to_vector_with_padding(dest: &mut Vec<u8>, source: &Vec<u8>, source_size_with_padding: usize) {
    let mut vec_to_append = vec![0; source_size_with_padding];
    let start_idx = source_size_with_padding - source.len();
    vec_to_append[start_idx..].copy_from_slice(source.as_slice());
    dest.extend_from_slice(vec_to_append.as_slice());
}
