package main

/*
   #include <stdlib.h>
*/
import "C"
import (
	"encoding/json"
	"fmt"
	"unsafe"

	"main/gethutil"
)

// TODO: Add proper error handling.  For example, return an int, where 0 means
// ok, and !=0 means error.
//
//export CreateTrace
func CreateTrace(configStr *C.char) *C.char {
	var config gethutil.TraceConfig
	err := json.Unmarshal([]byte(C.GoString(configStr)), &config)
	if err != nil {
		return C.CString(fmt.Sprintf("Failed to unmarshal config, err: %v", err))
	}

	executionResults, err := gethutil.Trace(config)
	if err != nil {
		return C.CString(fmt.Sprintf("Failed to run Trace, err: %v", err))
	}

	bytes, err := json.MarshalIndent(executionResults, "", "  ")
	if err != nil {
		return C.CString(fmt.Sprintf("Failed to marshal []ExecutionResult, err: %v", err))
	}

	return C.CString(string(bytes))
}

//export FreeString
func FreeString(str *C.char) {
	C.free(unsafe.Pointer(str))
}

func main() {
	var config gethutil.TraceConfig
	err := json.Unmarshal([]byte(
		"{\"chain_id\":\"0x53a\",\"history_hashes\":[],\"block_constants\":{\"coinbase\":\"0x0000000000000000000000000000000000000000\",\"timestamp\":\"0x75bcd15\",\"number\":\"0xcafe\",\"difficulty\":\"0x200000\",\"gas_limit\":\"0x2386f26fc10000\",\"base_fee\":\"0x0\"},\"accounts\":{\"0xfefefefefefefefefefefefefefefefefefefefe\":{\"address\":\"0xfefefefefefefefefefefefefefefefefefefefe\",\"nonce\":\"0x0\",\"balance\":\"0x56bc75e2d63100000\",\"code\":\"0x0061736d0100000001400960000060017f0060027f7f0060037f7f7f0060047f7f7f7f0060057f7f7f7f7f0060067f7f7f7f7f7f0060077f7f7f7f7f7f7f0060087f7f7f7f7f7f7f7f0002230203656e76095f65766d5f63616c6c000803656e760b5f65766d5f72657475726e0002030201000503010001071102046d61696e0002066d656d6f727902000a3401320041a08d064100411441004100410041004134100041a08d06413541c900410041004100410041e90010004100410010010b0b70010041000b6affffffffffffffffffffffffffffffffffffffff000000000000000000000000000000000000000000000000000000000000000000ffffffffffffffffffffffffffffffffffffffff000000000000000000000000000000000000000000000000000000000000000000\",\"storage\":{}},\"0x000000000000000000000000000000000000cafe\":{\"address\":\"0x000000000000000000000000000000000000cafe\",\"nonce\":\"0x0\",\"balance\":\"0x8ac7230489e80000\",\"code\":\"0x\",\"storage\":{}},\"0xffffffffffffffffffffffffffffffffffffffff\":{\"address\":\"0xffffffffffffffffffffffffffffffffffffffff\",\"nonce\":\"0x1\",\"balance\":\"0xdeadbeef\",\"code\":\"0x0061736d01000000010d0360000060017f0060027f7f0002130103656e760b5f65766d5f72657475726e0002030201000503010001071102046d61696e0001066d656d6f727902000a0a0108004100410010000b\",\"storage\":{}}},\"transactions\":[{\"from\":\"0x000000000000000000000000000000000000cafe\",\"to\":\"0xfefefefefefefefefefefefefefefefefefefefe\",\"nonce\":\"0x0\",\"gas_limit\":\"0x186a0\",\"value\":\"0x3e8\",\"gas_price\":\"0x1\",\"gas_fee_cap\":\"0x0\",\"gas_tip_cap\":\"0x0\",\"call_data\":\"0x\",\"access_list\":[],\"v\":0,\"r\":\"0x0\",\"s\":\"0x0\"}],\"logger_config\":{\"EnableMemory\":true,\"DisableStack\":false,\"DisableStorage\":false,\"EnableReturnData\":true}}",
	), &config)
	if err != nil {
		panic(err)
	}
	executionResults, err := gethutil.Trace(config)
	if err != nil {
		panic(err)
	}
	bytes, err := json.MarshalIndent(executionResults, "", "  ")
	if err != nil {
		panic(err)
	}
	println(string(bytes))
}
