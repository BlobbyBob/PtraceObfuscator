package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Not enough arguments")
		os.Exit(1)
	}

	file := os.Args[1]
	cmd := exec.Command("go", "run", "obfuscator.go", file) // todo integrate obfuscator here
	b, err := cmd.CombinedOutput()
	fmt.Println(string(b))
	if ee, isEE := err.(*exec.ExitError); isEE {
		if ee.ExitCode() != 0 {
			os.Exit(ee.ExitCode())
		}
	}

	cmd = exec.Command("go", "build", "-o", "runtime", "runtime.go")
	b, _ = cmd.CombinedOutput()
	fmt.Println(string(b))
	if ee, isEE := err.(*exec.ExitError); isEE {
		if ee.ExitCode() != 0 {
			os.Exit(ee.ExitCode())
		}
	}

	writeSourceFile("runtime", "loader/runtime.go", "Runtime")
	writeSourceFile(file+".obf", "loader/obf.go", "Obf")
	writeSourceFile(file+".obf.meta", "loader/meta.go", "Meta")

	cmd = exec.Command("go", "build", "-o", file+".packed", "loader.go")
	b, _ = cmd.CombinedOutput()
	fmt.Println(string(b))
	if ee, isEE := err.(*exec.ExitError); isEE {
		if ee.ExitCode() != 0 {
			os.Exit(ee.ExitCode())
		}
	}
}

func writeSourceFile(input, output, varname string) {
	in, err := os.OpenFile(input, os.O_RDONLY, 0)
	if err != nil {
		fmt.Println("file does not exist", err)
		os.Exit(1)
	}

	out, err := os.OpenFile(output, os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 0644)
	if err != nil {
		fmt.Println("can't open output file:", err)
		os.Exit(1)
	}

	if _, err := out.WriteString("package loader; var " + varname + " = []byte{"); err != nil {
		fmt.Println("can't write to file:", err)
		os.Exit(1)
	}

	buf := make([]byte, 2<<16) // todo maybe compress this in some way?
	for {
		n, err := in.Read(buf)
		if n > 0 {
			for _, b := range buf[:n] {
				if _, err := out.WriteString(fmt.Sprintf("%d, ", b)); err != nil {
					fmt.Println("can't write to file:", err)
					os.Exit(1)
				}
			}
		}
		if err == io.EOF {
			break
		} else if err != nil {
			panic(err)
		}
	}

	if _, err := out.WriteString("}"); err != nil {
		fmt.Println("can't write to file:", err)
		os.Exit(1)
	}

	_ = out.Close()
	_ = in.Close()
}
