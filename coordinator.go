// TODO: Make it portable across different kernels using CO-RE (https://thegraynode.io/posts/portable_bpf_programs/ or bpf2go)
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
	SourceType       string `yaml:"sourceType"`
	FilePath         string `yaml:"filePath"`
	FileOutputPath   string `yaml:"fileOutputPath"`
	CompileFlags     string `yaml:"compileFlags"`
	LoaderPath       string `yaml:"loaderPath"`
	LoaderOutputPath string `yaml:"loaderOutputPath"`
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

type CompileResult struct {
	name       string
	outputPath string
	err        error
}

// This is for the queue.
type DeployJob struct {
	host      HostConfig
	loaderBin string
	ebpfObj   string
}

type Context map[string]interface {}

type JobHandler interface {
	Start() error
	JobTransition(stepName string, next func(Context) error, ctx Context) error
}

type Task struct {}

func (t *Task) JobTransition(stepName string, next func(Context) error, ctx Context) error {
	log.Printf("Saved %s", stepName)
	return next(ctx)
}

func (t *Task) JobComplete(ctx Context) error {
	log.Printf("Job completed")
	return nil
}

func (t *Task) Start() error {
	deployConfigPath := os.Args[1]
	deployConfig, err := loadConfig(deployConfigPath)

	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// We add the file config and the first compilation in as a single stage because by only reading the config file
	// we'd do not get any action.
	loaderResultChan := compileLoader(deployConfig.EBPF.LoaderPath, deployConfig.EBPF.LoaderOutputPath)
	loaderResult := <-loaderResultChan

	if loaderResult.err != nil {
		log.Fatalf("Loader compilation failed: %v", loaderResult.err)
		// break TODO: How to stop the operation and log in DB this stage?
	}

	ctx := Context{
		"deployConfig": deployConfig,
	}

	return t.JobTransition("start", t.CompileEBPF, ctx)
}

func (t *Task) CompileEBPF(ctx Context) error {
	deployConfig := ctx["deployConfig"].(*DeployConfig)
	ebpfResultChan := compileEBPF(deployConfig.EBPF.FilePath, deployConfig.EBPF.FileOutputPath)
	ebpfResult := <-ebpfResultChan

	if ebpfResult.err != nil {
		log.Fatalf("eBPF compilation failed: %v", ebpfResult.err)
		// break TODO: How to stop the operation and log in DB this stage?
	}

	return t.JobTransition("compileEBPF", t.DeployToHost, nil)
}

func (t *Task) DeployToHost(ctx Context) error {
	return t.JobTransition("deployToHost", t.JobComplete, nil)
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

func compileLoader(loaderPath string, loaderOutputPath string) <-chan CompileResult {
	resultChannel := make(chan CompileResult)

	go func() {
		defer close(resultChannel)
		// We assume that always the architecture is AMD64 just for the PoC since this is the chip of my local machine.
		// for future implementation, I'll add support to compile with different flags.
		cmd := exec.Command(
			"go",
			"build",
			"-ldflags",
			"-extldflags \"-static\"",
			"-o",
			loaderOutputPath,
			loaderPath,
		)

		cmd.Env = append(os.Environ(),
			"GOOS=linux",
			"GOARCH=amd64",
			"CGO_ENABLED=0",
		)

		output, err := cmd.CombinedOutput()
		if err != nil {
			resultChannel <- CompileResult{"loader", "", fmt.Errorf("Failed to compile loader: %v: %s", err, output)}
			return
		}
		resultChannel <- CompileResult{"loader", loaderOutputPath, nil}
	}()

	return resultChannel
}

func compileEBPF(filePath string, ebpfObjOutputPath string) <-chan CompileResult {
	resultChannel := make(chan CompileResult)

	go func() {
		defer close(resultChannel)
		// TODO: Verify CO-RE or see the possibility to compile for a matrix of Kernels.
		cmd := exec.Command(
			"clang",
			"-O2",
			"-g",
			"-target",
			"bpf",
			"-c",
			filePath,
			"-o",
			ebpfObjOutputPath,
		)

		output, err := cmd.CombinedOutput()
		if err != nil {
			resultChannel <- CompileResult{"ebpf", "", fmt.Errorf("Failed to compile eBPF: %v\nOutput: %s", err, output)}
			return
		}

		resultChannel <- CompileResult{"ebpf", filePath + ".o", nil}
	}()

	return resultChannel
}

func deployToHost(deployJob DeployJob) error {
	address := deployJob.host.Address
	user := deployJob.host.User
	keyPath := deployJob.host.PrivateKeyPath

	userAndAddress := fmt.Sprintf("%s@%s", user, address)

	loaderBin := deployJob.loaderBin
	ebpfObj := deployJob.ebpfObj

	remoteLoader := "/tmp/loader"
	remoteObj := "/tmp/minimal.o"

	// 1. Copy the loader binary to the remote machine
	scpCmd1 := exec.Command("scp", "-i", keyPath, loaderBin, fmt.Sprintf("%s:%s", userAndAddress, remoteLoader))
	if out, err := scpCmd1.CombinedOutput(); err != nil {
		return fmt.Errorf("Failed to SCP loader: %v\nOutput: %s", err, out)
	}

	// 2. Copy the minimal.o eBPF object
	scpCmd2 := exec.Command("scp", "-i", keyPath, ebpfObj, fmt.Sprintf("%s:%s", userAndAddress, remoteObj))
	if out, err := scpCmd2.CombinedOutput(); err != nil {
		return fmt.Errorf("Failed to SCP eBPF .o file: %v\nOutput: %s", err, out)
	}

	// 3. SSH to run the loader
	runCmd := fmt.Sprintf("chmod +x %s && (sudo %s -obj %s > /tmp/loader.log 2>&1 & disown) && echo 'Loader started in background' && exit", remoteLoader, remoteLoader, remoteObj)

	remoteCmd := fmt.Sprintf("'%s'", runCmd)
	sshCmd := exec.Command("ssh", "-i", keyPath, userAndAddress, "bash", "-c", remoteCmd)

	out, err := sshCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("Loader execution failed: %v\nOutput: %s", err, out)
	}
	log.Printf("Loader ran successfully! Output:\n%s", out)

	return nil

	// 4. (Optional) Cleanup ephemeral files
	// cleanupCmd := fmt.Sprintf("rm %s %s", remoteLoader, remoteObj)
	// sshCleanup := exec.Command("ssh", "-i", keyPath, host, cleanupCmd)
	// if out, err := sshCleanup.CombinedOutput(); err != nil {
	// 	log.Printf("Cleanup warning: %v\nOutput: %s", err, out)
	// }
	// log.Println("Cleanup done, ephemeral agentless approach complete.")
}

func deployWorker(deployJobs <-chan DeployJob, results chan<- error) {
	for deployJob := range deployJobs {
		log.Printf("Starting deployment to host %s", deployJob.host.Address)
		err := deployToHost(deployJob)
		if err != nil {
			results <- fmt.Errorf("Failed to deploy to host %s: %v", deployJob.host.Address, err)
			continue
		}
		results <- nil
		log.Printf("Deployment to host %s completed successfully", deployJob.host.Address)
	}
}

func main() {
	// deployConfigPath := os.Args[1]

	// deployConfig, err := loadConfig(deployConfigPath)
	// if err != nil {
	// 	log.Fatalf("Failed to load config: %v", err)
	// }

	var job JobHandler = &Task{}
	err := job.Start()
	if err != nil {
		log.Fatalf("Failed to start job: %v", err)
	}

	// loaderResultChan := compileLoader(deployConfig.EBPF.LoaderPath, deployConfig.EBPF.LoaderOutputPath)
	// ebpfResultChan := compileEBPF(deployConfig.EBPF.FilePath, deployConfig.EBPF.FileOutputPath)

	// loaderResult := <-loaderResultChan
	// ebpfResult := <-ebpfResultChan

	// if loaderResult.err != nil {
	// 	log.Fatalf("Loader compilation failed: %v", loaderResult.err)
	// }
	// if ebpfResult.err != nil {
	// 	log.Fatalf("eBPF compilation failed: %v", ebpfResult.err)
	// }

	// log.Printf("Loader compiled successfully: %s", loaderResult.outputPath)
	// log.Printf("eBPF compiled successfully: %s", ebpfResult.outputPath)

	// loaderBin := loaderResult.outputPath
	// ebpfObj := ebpfResult.outputPath

	// numWorkers := 2  // TODO: Investigate more about this.
	// deployJobs := make(chan DeployJob, numWorkers)
	// deployResults := make(chan error, numWorkers)

	// for i := 0; i < numWorkers; i++ {
	// 	go deployWorker(deployJobs, deployResults)
	// }

	// for _, host := range deployConfig.Hosts {
	// 	deployJobs <- DeployJob{host, loaderBin, ebpfObj}
	// }
	// close(deployJobs)

	// for i := 0; i < numWorkers; i++ {
	// 	if err := <-deployResults; err != nil {
	// 		log.Printf("Failed to deploy to host %s: %v", deployConfig.Hosts[i].Address, err)
	// 	}
	// }
}
