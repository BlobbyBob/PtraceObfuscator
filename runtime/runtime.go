package runtime

import (
	"encoding/json"
	"fmt"
	"github.com/BlobbyBob/NOPfuscator/common"
	"io/ioutil"
	"os"
	"syscall"
)

type Runtime struct {
	Metadata []common.ObfuscatedInstruction
	Process *os.Process
	ProcessState *os.ProcessState
	Event chan syscall.WaitStatus
}

func NewRuntime() *Runtime {
	runtime := new(Runtime)
	runtime.Event = make(chan syscall.WaitStatus)
	return runtime
}

func (r *Runtime) ReadMetadata(filename string) error {
	metadataFile, err := ioutil.ReadFile(filename)
	if err != nil {
		return err
	}

	var metadataRaw []common.ExportObfuscatedInstruction
	if err := json.Unmarshal(metadataFile, &metadataRaw); err != nil {
		return err
	}

	r.Metadata, err = common.ImportObfuscatedInstructions(metadataRaw)
	if err != nil {
		return err
	}

	return nil
}

func (r *Runtime) StartAndBreakProgram(filename string, args []string) error {
	p, err := os.StartProcess(filename, args, &os.ProcAttr{
		Files: []*os.File{os.Stdin, os.Stdout, os.Stderr},
		Sys: &syscall.SysProcAttr{
			Ptrace: true,
			Pdeathsig: syscall.SIGCHLD,
		},
	})
	if err != nil {
		return err
	}
	r.Process = p

	processState, err := p.Wait()
	if err != nil {
		return err
	}
	r.ProcessState = processState

	waitStatus, _ := processState.Sys().(syscall.WaitStatus)
	if waitStatus.TrapCause() < 0 {
		fmt.Printf("Warning. Unexpected process state: 0x%x\n", waitStatus)
	}

	go r.waitForEvent()
	return nil
}

func (r *Runtime) waitForEvent() {
	for {
		fmt.Println("Waiting for process...")
		processState, err := r.Process.Wait()
		if err != nil {
			// Can't wait because process ended
			fmt.Println("Terminating waitForEvent loop")
			break
		}
		r.ProcessState = processState

		waitStatus, _ := processState.Sys().(syscall.WaitStatus)
		r.Event <- waitStatus
	}
}

func (r *Runtime) SetBreakpoints() {

}

func (r *Runtime) PerformInstruction() {

}

func (r *Runtime) Continue() error {
	if err := syscall.PtraceCont(r.Process.Pid, 0); err != nil {
		return err
	}
	return nil
}
