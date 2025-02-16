package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
)

func main() {
	host := os.Args[1]
	loaderBin := os.Args[2]
	ebpfObj := os.Args[3]
	keyPath := os.Args[4]

	remoteLoader := "/tmp/loader"
	remoteObj := "/tmp/minimal.o"

	// 1. Copy the loader binary to the remote machine
	scpCmd1 := exec.Command("scp", "-i", keyPath, loaderBin, fmt.Sprintf("%s:%s", host, remoteLoader))
	if out, err := scpCmd1.CombinedOutput(); err != nil {
		log.Fatalf("Failed to SCP loader: %v\nOutput: %s", err, out)
	}

	// 2. Copy the minimal.o eBPF object
	scpCmd2 := exec.Command("scp", "-i", keyPath, ebpfObj, fmt.Sprintf("%s:%s", host, remoteObj))
	if out, err := scpCmd2.CombinedOutput(); err != nil {
		log.Fatalf("Failed to SCP eBPF .o file: %v\nOutput: %s", err, out)
	}

	// 3. SSH to run the loader
	runCmd := fmt.Sprintf("chmod +x %s && (sudo %s -obj %s > /tmp/loader.log 2>&1 & disown) && echo 'Loader started in background' && exit", remoteLoader, remoteLoader, remoteObj)

	// SSH COMMAND
	remoteCmd := fmt.Sprintf("'%s'", runCmd)
	sshCmd := exec.Command("ssh", "-i", keyPath, host, "bash", "-c", remoteCmd)

	out, err := sshCmd.CombinedOutput()
	if err != nil {
		log.Fatalf("Loader execution failed: %v\nOutput: %s", err, out)
	}
	log.Printf("Loader ran successfully! Output:\n%s", out)

	// 4. (Optional) Cleanup ephemeral files
	// cleanupCmd := fmt.Sprintf("rm %s %s", remoteLoader, remoteObj)
	// sshCleanup := exec.Command("ssh", "-i", keyPath, host, cleanupCmd)
	// if out, err := sshCleanup.CombinedOutput(); err != nil {
	// 	log.Printf("Cleanup warning: %v\nOutput: %s", err, out)
	// }
	// log.Println("Cleanup done, ephemeral agentless approach complete.")
}
