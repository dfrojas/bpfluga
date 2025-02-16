compile-bpf:
	clang -O2 -g -target bpf -c bpf/minimal.c -o bpf/minimal.o

compile-loader:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags '-extldflags "-static"' -o loader/loader loader/loader.go

compile-coordinator:
	go build -o coordinator coordinator.go

load:
	sudo ./coordinator root@142.93.126.252 ./loader/loader ./bpf/minimal.o /Users/diegorojas/.ssh/id_rsa_eBPFTests
