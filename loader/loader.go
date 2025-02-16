package main

import (
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	_ "github.com/cilium/ebpf/rlimit" // Auto-raise rlimit if needed
)

var (
	objPath = flag.String("obj", "./bpf/minimal.o", "Path to eBPF .o file")
)

func main() {
	flag.Parse()

	// 1. Load the compiled eBPF .o into a CollectionSpec
	spec, err := ebpf.LoadCollectionSpec(*objPath)
	if err != nil {
		log.Fatalf("Failed to load eBPF collection: %v", err)
	}

	// 2. Create a Collection from the spec
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("Failed to create eBPF collection: %v", err)
	}
	defer coll.Close()

	// 3. Retrieve the program by its SEC name
	prog := coll.Programs["handle_clone"]
	if prog == nil {
		log.Fatalf("Program 'kprobe_sys_clone' not found")
	}
	defer prog.Close()

	// 4. Attach the program via kprobe to sys_clone
	kprobe, err := link.Kprobe("sys_clone", prog, nil)
	if err != nil {
		log.Fatalf("Failed to attach kprobe: %v", err)
	}
	//defer kprobe.Close()

	fmt.Println("Atajado kprobe on sys_clone. Check trace output with:")
	fmt.Println("    sudo cat /sys/kernel/debug/tracing/trace_pipe")
	fmt.Println("Press Ctrl-C or kill this process to detach kprobe (unless pinned).")

	for {
		time.Sleep(1 * time.Second)
	}

	// fmt.Println("eBPF program loaded and attached. Check `sudo cat /sys/kernel/debug/tracing/trace_pipe`")
	// Keep running or exit? For ephemeral usage, you can just exit
	// and the eBPF program remains attached only if pinned or until the program object is closed.

	// If you want it to persist after exit, you'd pin it or hold the program open. For demonstration:
	// (Uncomment if you want to pin)
	// err = prog.Pin("/sys/fs/bpf/minimal_prog")
	// if err != nil {
	//     log.Printf("Warning: failed to pin eBPF program: %v", err)
	// }

	// Wait or exit. We'll exit right away.
}
