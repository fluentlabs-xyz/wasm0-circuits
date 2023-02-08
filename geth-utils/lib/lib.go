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
		"{\"chain_id\":\"0x53a\",\"history_hashes\":[],\"block_constants\":{\"coinbase\":\"0x0000000000000000000000000000000000000000\",\"timestamp\":\"0x75bcd15\",\"number\":\"0xcafe\",\"difficulty\":\"0x200000\",\"gas_limit\":\"0x2386f26fc10000\",\"base_fee\":\"0x0\"},\"accounts\":{\"0x0000000000000000000000000000000000000020\":{\"address\":\"0x0000000000000000000000000000000000000020\",\"nonce\":\"0x0\",\"balance\":\"0x100000\",\"code\":\"0x\",\"storage\":{}},\"0x0000000000000000000000000000000000cafe01\":{\"address\":\"0x0000000000000000000000000000000000cafe01\",\"nonce\":\"0x0\",\"balance\":\"0x100000\",\"code\":\"0x\",\"storage\":{}},\"0x0000000000000000000000000000000000000010\":{\"address\":\"0x0000000000000000000000000000000000000010\",\"nonce\":\"0x0\",\"balance\":\"0x100000\",\"code\":\"0x41ff00100b\",\"storage\":{}}},\"transactions\":[{\"from\":\"0x0000000000000000000000000000000000cafe01\",\"to\":\"0x0000000000000000000000000000000000000010\",\"nonce\":\"0x0\",\"gas_limit\":\"0xf4240\",\"value\":\"0x0\",\"gas_price\":\"0x1\",\"gas_fee_cap\":\"0x0\",\"gas_tip_cap\":\"0x0\",\"call_data\":\"0x\",\"access_list\":[],\"v\":0,\"r\":\"0x0\",\"s\":\"0x0\"}],\"logger_config\":{\"EnableMemory\":true,\"DisableStack\":false,\"DisableStorage\":false,\"EnableReturnData\":true}}",
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
