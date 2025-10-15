module chimney3

go 1.25.1

require (
	github.com/xtaci/kcp-go/v5 v5.6.24
	golang.org/x/crypto v0.43.0
	golang.org/x/net v0.46.0
	gvisor.dev/gvisor v0.0.0-20250828211149-1f30edfbb5d4
	tun2proxylib v0.0.1
)

require (
	github.com/google/btree v1.1.2 // indirect
	github.com/klauspost/cpuid/v2 v2.2.6 // indirect
	github.com/klauspost/reedsolomon v1.12.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/tjfoc/gmsm v1.4.1 // indirect
	golang.org/x/sys v0.37.0 // indirect
	golang.org/x/time v0.12.0 // indirect
)

replace tun2proxylib => github.com/Evan2698/tun2proxylib v0.0.1
