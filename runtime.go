package main

import (
	"fmt"
	. "github.com/BlobbyBob/NOPfuscator/runtime"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	if len(os.Args) < 3 {
		panic("Arguments missing.\n Usage: runtime myprogram ...args")
	}

	obfBinaryFilename := os.Args[1] // + ".obf"
	metadataFilename := os.Args[1] + ".obf.meta"

	runtime := NewRuntime()
	if err := runtime.ReadMetadata(metadataFilename); err != nil {
		panic(err)
	}

	signals := make(chan os.Signal, 1)
	signal.Notify(signals)
	go func() {
		for {
			s := <-signals
			if s == syscall.SIGINT {
				fmt.Println("Interrupt. Terminating...")
				os.Exit(0)
			} else if s == syscall.SIGCHLD {
				fmt.Println("Child Exited. Terminating...")
				//os.Exit(0)
			} else {
				fmt.Println("Received signal:", s)
			}
		}
	}()

	fmt.Printf("Starting program '%s' with args %v\n", obfBinaryFilename, os.Args[1:])
	if err := runtime.StartAndBreakProgram(obfBinaryFilename, os.Args[1:]); err != nil {
		panic(err)
	}

	stop := make(chan interface{})

	go func() {
		<-runtime.Event
		stop <- true
	}()

	if err := runtime.Continue(); err != nil {
		panic(err)
	}

	<-stop
	fmt.Println("Done")

}
