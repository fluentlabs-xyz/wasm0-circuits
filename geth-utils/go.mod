module main

go 1.16

require (
	github.com/ethereum/go-ethereum v1.10.18
	github.com/holiman/uint256 v1.2.0
)

// Replace wazero with local version
replace github.com/tetratelabs/wazero v1.0.0-pre.7 => ../../zkwasm-wazero

// Uncomment for debugging
replace github.com/ethereum/go-ethereum => ../../zkwasm-geth
