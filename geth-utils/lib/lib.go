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
		"{\"chain_id\":\"0x53a\",\"history_hashes\":[],\"block_constants\":{\"coinbase\":\"0x0000000000000000000000000000000000000000\",\"timestamp\":\"0x75bcd15\",\"number\":\"0x0\",\"difficulty\":\"0x200000\",\"gas_limit\":\"0x2386f26fc10000\",\"base_fee\":\"0x0\"},\"accounts\":{\"0x000000000000000000000000000000000cafe111\":{\"address\":\"0x000000000000000000000000000000000cafe111\",\"nonce\":\"0x0\",\"balance\":\"0x8ac7230489e80000\",\"code\":\"0x0061736d0100000001220660017f0060000060027f7f0060037f7f7f0060047f7f7f7f0060057f7f7f7f7f0002f5031903656e76095f65766d5f73746f70000103656e760c5f65766d5f61646472657373000003656e760b5f65766d5f63616c6c6572000003656e760d5f65766d5f6761736c696d6974000003656e760c5f65766d5f62617365666565000003656e760f5f65766d5f646966666963756c7479000003656e760b5f65766d5f6f726967696e000003656e76115f65766d5f63616c6c6461746173697a65000003656e760e5f65766d5f63616c6c76616c7565000003656e760d5f65766d5f6761737072696365000003656e76135f65766d5f72657475726e6461746173697a65000003656e760c5f65766d5f62616c616e6365000203656e760b5f65766d5f6e756d626572000003656e760c5f65766d5f636861696e6964000003656e760a5f65766d5f736c6f6164000203656e760b5f65766d5f7373746f7265000203656e760b5f65766d5f637265617465000403656e760c5f65766d5f63726561746532000503656e760b5f65766d5f72657475726e000203656e760b5f65766d5f726576657274000203656e760d5f65766d5f636f646573697a65000003656e76105f65766d5f73656c6662616c616e6365000003656e76105f65766d5f657874636f646568617368000203656e76105f65766d5f657874636f646573697a65000203656e76115f65766d5f63616c6c646174616c6f61640002030201010503010001071102046d61696e0019066d656d6f727902000a0e010c00410141ffffffff076a1a0b\",\"storage\":{}},\"0x000000000000000000000000000000000cafe222\":{\"address\":\"0x000000000000000000000000000000000cafe222\",\"nonce\":\"0x0\",\"balance\":\"0x8ac7230489e80000\",\"code\":\"0x\",\"storage\":{}}},\"transactions\":[{\"from\":\"0x000000000000000000000000000000000cafe222\",\"to\":\"0x000000000000000000000000000000000cafe111\",\"nonce\":\"0x0\",\"gas_limit\":\"0xf4240\",\"value\":\"0x0\",\"gas_price\":\"0x1\",\"gas_fee_cap\":\"0x0\",\"gas_tip_cap\":\"0x0\",\"call_data\":\"0x\",\"access_list\":[],\"v\":0,\"r\":\"0x0\",\"s\":\"0x0\"}],\"logger_config\":{\"EnableMemory\":true,\"DisableStack\":false,\"DisableStorage\":false,\"EnableReturnData\":true}}",
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
