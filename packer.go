package main

import (
	"encoding/json"
	"fmt"
	"github.com/BlobbyBob/NOPfuscator/common"
	"github.com/BlobbyBob/NOPfuscator/obfuscator"
	"log"
	"os"
	"os/exec"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Not enough arguments")
		os.Exit(1)
	}

	file := os.Args[1]
	log.Print("Obfuscating ", file)
	elf, metadata, err := obfuscator.Obfuscate(file)
	if err != nil {
		log.Fatal(err)
	}

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
		if _, err := out.WriteString(fmt.Sprintf("%d, ", b)); err != nil {
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
