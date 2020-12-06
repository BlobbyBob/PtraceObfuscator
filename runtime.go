package main

import (
	"encoding/json"
	"fmt"
	"github.com/BlobbyBob/NOPfuscator/common"
	"io/ioutil"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	if len(os.Args) < 3 {
		panic("Arguments missing.\n Usage: runtime myprogram.obf myprogram.meta")
	}

	obfBinaryFilename := os.Args[1]
	metadataFilename := os.Args[2]

	metadataFile, err := ioutil.ReadFile(metadataFilename)
	if err != nil {
		panic(err)
	}

	var metadataRaw []common.ExportObfuscatedInstruction
	if err := json.Unmarshal(metadataFile, &metadataRaw); err != nil {
		panic(err)
	}

	metadata, err := common.ImportObfuscatedInstructions(metadataRaw)
	if err != nil {
		panic(err)
	}

	fmt.Println("Number of obfuscated instructions:", len(metadata))

	signals := make(chan os.Signal, 1)
	signal.Notify(signals)
	go func() {
		for {
			s := <-signals
			fmt.Println("Got signal", s)
		}
	}()


	p, err := os.StartProcess(obfBinaryFilename, os.Args[2:], &os.ProcAttr{
		Files: []*os.File{os.Stdin, os.Stdout, os.Stderr},
		Sys: &syscall.SysProcAttr{
			Ptrace: true,
			Pdeathsig: syscall.SIGCHLD,
		},
	})
	if err != nil {
		panic(err)
	}

	processState, err := p.Wait()
	if err != nil {
		panic(err)
	}

	waitStatus, _ := processState.Sys().(syscall.WaitStatus)
	fmt.Println("Exited?", waitStatus.Exited())

	var reg syscall.PtraceRegs
	if err := syscall.PtraceGetRegs(p.Pid, &reg); err != nil {
		panic(err)
	}

	fmt.Printf("RIP: 0x%016x\n", reg.Rip)

	fmt.Println("Running program to completion")

	if err := syscall.PtraceCont(p.Pid, 0); err != nil {
		panic(err)
	}

	if _, err = p.Wait(); err != nil {
		panic(err)
	}

	fmt.Println("Done")

}
