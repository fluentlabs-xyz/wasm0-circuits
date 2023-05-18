module main

go 1.18

require (
	github.com/ethereum/go-ethereum v1.11.6
	github.com/holiman/uint256 v1.2.2-0.20230321075855-87b91420868c
	github.com/imdario/mergo v0.3.15
	github.com/scroll-tech/go-ethereum v1.11.5
)

require (
	github.com/StackExchange/wmi v0.0.0-20180116203802-5d049714c4a6 // indirect
	github.com/VictoriaMetrics/fastcache v1.6.0 // indirect
	github.com/btcsuite/btcd v0.20.1-beta // indirect
	github.com/cespare/xxhash/v2 v2.2.0 // indirect
	github.com/deckarep/golang-set v0.0.0-20180603214616-504e848d77ea // indirect
	github.com/go-ole/go-ole v1.2.1 // indirect
	github.com/go-stack/stack v1.8.1 // indirect
	github.com/golang/snappy v0.0.5-0.20220116011046-fa5810519dcb // indirect
	github.com/gorilla/websocket v1.4.2 // indirect
	github.com/hashicorp/golang-lru v0.5.5-0.20210104140557-80c98217689d // indirect
	github.com/holiman/bloomfilter/v2 v2.0.3 // indirect
	github.com/iden3/go-iden3-crypto v0.0.12 // indirect
	github.com/mattn/go-runewidth v0.0.9 // indirect
	github.com/olekukonko/tablewriter v0.0.5 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/prometheus/tsdb v0.7.1 // indirect
	github.com/sbinet/wasm v0.0.0-20170316085644-fb052fb8d320 // indirect
	github.com/scroll-tech/zktrie v0.5.3 // indirect
	github.com/shirou/gopsutil v3.21.4-0.20210419000835-c7a38de76ee5+incompatible // indirect
	github.com/syndtr/goleveldb v1.0.1-0.20210819022825-2ae1ddf74ef7 // indirect
	github.com/tklauser/go-sysconf v0.3.10 // indirect
	github.com/tklauser/numcpus v0.4.0 // indirect
	github.com/wasm0/zkwasm-gas-injector v0.0.0-20230417162546-ab3ab673b1f7 // indirect
	github.com/wasm0/zkwasm-wasmi v0.0.0-20230518124118-1ec41428152c // indirect
	golang.org/x/crypto v0.6.0 // indirect
	golang.org/x/sys v0.6.0 // indirect
	gopkg.in/natefinch/npipe.v2 v2.0.0-20160621034901-c1b8fa8bdcce // indirect
)

// replace github.com/wasm0/zkwasm-gas-injector v0.0.0-20230411142508-c7b0f5abfee3 => ../../zkwasm-gas-injector

//replace github.com/ethereum/go-ethereum v1.10.18 => github.com/wasm0/zkwasm-geth v1.10.23-zkevm.0.20230424123711-e5a412f5a80d
replace github.com/scroll-tech/go-ethereum => ../../wasm0-geth2
