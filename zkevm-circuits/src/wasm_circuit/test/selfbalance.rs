#[cfg(test)]
mod selfbalance_tests {
    use eth_types::bytecode;
    use eth_types::Bytecode;
    use eth_types::evm_types::OpcodeId;
    use eth_types::geth_types::GethData;
    use mock::test_ctx::helpers::*;
    use mock::test_ctx::TestContext;
    use bus_mapping::circuit_input_builder::ExecState;
    use bus_mapping::mocks::BlockData;

    #[test]
    fn selfbalance_circuit_impl() {
        let res_mem_address = 0x7f;
        let code = bytecode! {
            I32Const[res_mem_address]
            SELFBALANCE
        };

        // Get the execution steps from the external tracer
        let block: GethData = TestContext::<2, 1>::new(
            None,
            account_0_code_account_1_no_code(code),
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
            .find(|step| step.exec_state == ExecState::Op(OpcodeId::SELFBALANCE))
            .unwrap();

    }
}