package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"github.com/BlobbyBob/NOPfuscator/common"
	"github.com/BlobbyBob/NOPfuscator/obfuscator"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
)

// Packer
//
// The packer produces a single standalone obfuscated binary by compiling the runtime
// with the obfuscated binary and the metadata integrated as binary buffers.
func main() {
	nop := flag.Bool("nop", false, "Use NOPs instead of random data")
	var file string
	flag.StringVar(&file, "f", "", "ELF file. Existing files with suffixes .obf, .strip and .packed in directory of the file will be overwritten")
	flag.Parse()

	if file == "" {
		fmt.Println("Missing argument: filename")
		os.Exit(1)
	}

	log.Print("Obfuscating ", file)
	repl := 0
	if !*nop {
		repl = obfuscator.Rand
	}

	execute("strip", "-s", "-o", file+".strip", file)
	elf, metadata, err := obfuscator.Obfuscate(file+".strip", obfuscator.Linear|repl)
	if err != nil {
		log.Fatal(err)
	}

	_ = ioutil.WriteFile(file+".obf", elf, 0644)

	metadataJson, err := json.Marshal(common.ExportObfuscatedInstructions(*metadata))
	if err != nil {
		log.Fatal(err)
	}

	writeSourceFile(elf, "bin/obf.go", "Obf")
	writeSourceFile(metadataJson, "bin/meta.go", "Meta")

	log.Print("Packing binary")
	execute("go", "build", "-o", file+".packed", "runtime.go")
	log.Print("Stripping symbols")
	execute("strip", "-s", file+".packed")
}

// A simple utility for executing a program on the command line
func execute(name string, arg ...string) {
	cmd := exec.Command(name, arg...)
	b, err := cmd.CombinedOutput()
	fmt.Println(string(b))
	if ee, isEE := err.(*exec.ExitError); isEE {
		if ee.ExitCode() != 0 {
			os.Exit(ee.ExitCode())
		}
	}
}

// Write a binary buffer into a Go source file
func writeSourceFile(input []byte, output, varname string) {
	out, err := os.OpenFile(output, os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 0644)
	if err != nil {
		fmt.Println("can't open output file:", err)
		os.Exit(1)
	}

	if _, err := out.WriteString("package bin; var " + varname + " = []byte{"); err != nil {
		fmt.Println("can't write to file:", err)
		os.Exit(1)
	}

	for _, b := range input {
		if _, err := out.WriteString(fmt.Sprintf("%d,", b)); err != nil {
			fmt.Println("can't write to file:", err)
			os.Exit(1)
		}
	}

	if _, err := out.WriteString("}"); err != nil {
		fmt.Println("can't write to file:", err)
		os.Exit(1)
	}

	_ = out.Close()
}
