package main

import (
	"github.com/BlobbyBob/NOPfuscator/obfuscator"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		panic("Argument missing: file")
	}
	filename := os.Args[1]

	err := obfuscator.Obfuscate(filename)
	if err != nil {
		panic(err)
	}

}
