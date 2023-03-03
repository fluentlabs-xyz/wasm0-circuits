package gethutil

import (
	"encoding/json"
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/eth/tracers/logger"
	"github.com/ethereum/go-ethereum/params"
	"math/big"
)

type Block struct {
	Coinbase   common.Address `json:"coinbase"`
	Timestamp  *hexutil.Big   `json:"timestamp"`
	Number     *hexutil.Big   `json:"number"`
	Difficulty *hexutil.Big   `json:"difficulty"`
	GasLimit   *hexutil.Big   `json:"gas_limit"`
	BaseFee    *hexutil.Big   `json:"base_fee"`
}

type Account struct {
	Nonce   hexutil.Uint64              `json:"nonce"`
	Balance *hexutil.Big                `json:"balance"`
	Code    hexutil.Bytes               `json:"code"`
	Storage map[common.Hash]common.Hash `json:"storage"`
}

type Transaction struct {
	From       common.Address  `json:"from"`
	To         *common.Address `json:"to"`
	Nonce      hexutil.Uint64  `json:"nonce"`
	Value      *hexutil.Big    `json:"value"`
	GasLimit   hexutil.Uint64  `json:"gas_limit"`
	GasPrice   *hexutil.Big    `json:"gas_price"`
	GasFeeCap  *hexutil.Big    `json:"gas_fee_cap"`
	GasTipCap  *hexutil.Big    `json:"gas_tip_cap"`
	CallData   hexutil.Bytes   `json:"call_data"`
	AccessList []struct {
		Address     common.Address `json:"address"`
		StorageKeys []common.Hash  `json:"storage_keys"`
	} `json:"access_list"`
}

type TraceConfig struct {
	ChainID *hexutil.Big `json:"chain_id"`
	// HistoryHashes contains most recent 256 block hashes in history,
	// where the lastest one is at HistoryHashes[len(HistoryHashes)-1].
	HistoryHashes []*hexutil.Big             `json:"history_hashes"`
	Block         Block                      `json:"block_constants"`
	Accounts      map[common.Address]Account `json:"accounts"`
	Transactions  []Transaction              `json:"transactions"`
	LoggerConfig  *logger.Config             `json:"logger_config"`
}

func Trace(config TraceConfig) ([]*logger.WasmExecutionResult, error) {
	chainConfig := params.ChainConfig{
		ChainID:             toBigInt(config.ChainID),
		HomesteadBlock:      big.NewInt(0),
		DAOForkBlock:        big.NewInt(0),
		DAOForkSupport:      true,
		EIP150Block:         big.NewInt(0),
		EIP150Hash:          common.Hash{},
		EIP155Block:         big.NewInt(0),
		EIP158Block:         big.NewInt(0),
		ByzantiumBlock:      big.NewInt(0),
		ConstantinopleBlock: big.NewInt(0),
		PetersburgBlock:     big.NewInt(0),
		IstanbulBlock:       big.NewInt(0),
		MuirGlacierBlock:    big.NewInt(0),
		BerlinBlock:         big.NewInt(0),
		LondonBlock:         big.NewInt(0),
		WebAssemblyBlock:    big.NewInt(0),
	}

	var txsGasLimit uint64
	blockGasLimit := toBigInt(config.Block.GasLimit).Uint64()
	messages := make([]types.Message, len(config.Transactions))
	for i, tx := range config.Transactions {
		// If gas price is specified directly, the tx is treated as legacy type.
		if tx.GasPrice != nil {
			tx.GasFeeCap = tx.GasPrice
			tx.GasTipCap = tx.GasPrice
		}

		txAccessList := make(types.AccessList, len(tx.AccessList))
		for i, accessList := range tx.AccessList {
			txAccessList[i].Address = accessList.Address
			txAccessList[i].StorageKeys = accessList.StorageKeys
		}
		messages[i] = types.NewMessage(
			tx.From,
			tx.To,
			uint64(tx.Nonce),
			toBigInt(tx.Value),
			uint64(tx.GasLimit),
			toBigInt(tx.GasPrice),
			toBigInt(tx.GasFeeCap),
			toBigInt(tx.GasTipCap),
			tx.CallData,
			txAccessList,
			false,
		)

		txsGasLimit += uint64(tx.GasLimit)
	}
	if txsGasLimit > blockGasLimit {
		return nil, fmt.Errorf("txs total gas: %d Exceeds block gas limit: %d", txsGasLimit, blockGasLimit)
	}

	blockCtx := vm.BlockContext{
		CanTransfer: core.CanTransfer,
		Transfer:    core.Transfer,
		GetHash: func(n uint64) common.Hash {
			number := config.Block.Number.ToInt().Uint64()
			if number > n && number-n <= 256 {
				index := uint64(len(config.HistoryHashes)) - number + n
				return common.BigToHash(toBigInt(config.HistoryHashes[index]))
			}
			return common.Hash{}
		},
		Coinbase:    config.Block.Coinbase,
		BlockNumber: toBigInt(config.Block.Number),
		Time:        toBigInt(config.Block.Timestamp),
		Difficulty:  toBigInt(config.Block.Difficulty),
		BaseFee:     toBigInt(config.Block.BaseFee),
		GasLimit:    blockGasLimit,
	}

	// Setup state db with accounts from argument
	stateDB, _ := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	for address, account := range config.Accounts {
		stateDB.SetNonce(address, uint64(account.Nonce))
		stateDB.SetCode(address, account.Code)
		if account.Balance != nil {
			stateDB.SetBalance(address, toBigInt(account.Balance))
		}
		for key, value := range account.Storage {
			stateDB.SetState(address, key, value)
		}
		// 		if len(account.Code) > 0 {
		// 			_ = os.WriteFile(fmt.Sprintf("%s.wasm", address.Hex()), account.Code, os.ModePerm)
		// 		}
	}
	stateDB.Finalise(true)

	// Run the transactions with tracing enabled.
	executionResults := make([]*logger.WasmExecutionResult, len(config.Transactions))
	for i, message := range messages {
		tracer := logger.NewWebAssemblyLogger(config.LoggerConfig)
		evm := vm.NewEVM(blockCtx, core.NewEVMTxContext(message), stateDB, &chainConfig, vm.Config{Debug: true, Tracer: tracer, NoBaseFee: true})

		_, err := core.ApplyMessage(evm, message, new(core.GasPool).AddGas(message.Gas()))
		if err != nil {
			return nil, fmt.Errorf("Failed to apply config.Transactions[%d]: %w", i, err)
		}
		stateDB.Finalise(true)

		rawTrace, err := tracer.GetResult()
		if err != nil {
			return nil, err
		}
		res := &logger.WasmExecutionResult{}
		if err := json.Unmarshal(rawTrace, res); err != nil {
			return nil, err
		}
		executionResults[i] = res
	}

	return executionResults, nil
}
