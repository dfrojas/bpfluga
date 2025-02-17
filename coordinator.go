package main

import (
	"fmt"
	"gopkg.in/yaml.v3"
	"log"
	"os"
	"os/exec"
)

type HostConfig struct {
	Name           string `yaml:"name"`
	Address        string `yaml:"address"`
	Port           int    `yaml:"port"`
	User           string `yaml:"user"`
	PrivateKeyPath string `yaml:"privateKeyPath"`
}

type EBPFConfig struct {
	SourceType   string `yaml:"sourceType"`
	FilePath     string `yaml:"file_path"`
	CompileFlags string `yaml:"compileFlags"`
}

type MetricsConfig struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
}

type DeployConfig struct {
	Hosts   []HostConfig    `yaml:"hosts"`
	EBPF    EBPFConfig      `yaml:"ebpf"`
	Metrics []MetricsConfig `yaml:"metrics"`
}

func loadConfig(filename string) (*DeployConfig, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("Failed to read config file: %v", err)
	}

	var deployConfig DeployConfig
	err = yaml.Unmarshal(data, &deployConfig)
	if err != nil {
		return nil, fmt.Errorf("Failed to unmarshal config: %v", err)
	}

	return &deployConfig, nil
}

func main() {

	deployConfigPath := os.Args[1]

	deployConfig, err := loadConfig(deployConfigPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	host := deployConfig.Hosts[0]

	address := host.Address
	user := host.User

	userAndAddress := fmt.Sprintf("%s@%s", user, address)

	keyPath := host.PrivateKeyPath
	// loaderBin := deployConfig.EBPF.FilePath -> Coordinador debería compilar el loader?
	loaderBin := "./loader/loader"
	ebpfObj := "./bpf/minimal.o" // TODO: compilar el ebpfObj?

	remoteLoader := "/tmp/loader"
	remoteObj := "/tmp/minimal.o"

	// 1. Copy the loader binary to the remote machine
	scpCmd1 := exec.Command("scp", "-i", keyPath, loaderBin, fmt.Sprintf("%s:%s", userAndAddress, remoteLoader))
	if out, err := scpCmd1.CombinedOutput(); err != nil {
		log.Fatalf("Failed to SCP loader: %v\nOutput: %s", err, out)
	}

	// 2. Copy the minimal.o eBPF object
	scpCmd2 := exec.Command("scp", "-i", keyPath, ebpfObj, fmt.Sprintf("%s:%s", userAndAddress, remoteObj))
	if out, err := scpCmd2.CombinedOutput(); err != nil {
		log.Fatalf("Failed to SCP eBPF .o file: %v\nOutput: %s", err, out)
	}

	// 3. SSH to run the loader
	runCmd := fmt.Sprintf("chmod +x %s && (sudo %s -obj %s > /tmp/loader.log 2>&1 & disown) && echo 'Loader started in background' && exit", remoteLoader, remoteLoader, remoteObj)

	// SSH COMMAND
	remoteCmd := fmt.Sprintf("'%s'", runCmd)
	sshCmd := exec.Command("ssh", "-i", keyPath, userAndAddress, "bash", "-c", remoteCmd)

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
