package main

import (
	"encoding/json"
	"github.com/BlobbyBob/NOPfuscator/common"
	"github.com/BlobbyBob/NOPfuscator/obfuscator"
	"io/ioutil"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		panic("Argument missing: file")
	}
	filename := os.Args[1]

	metadata, err := obfuscator.Obfuscate(filename)
	if err != nil {
		panic(err)
	}

	metadataJson, err := json.Marshal(common.ExportObfuscatedInstructions(*metadata))
	if err != nil {
		panic(err)
	}

	if err := ioutil.WriteFile(filename + ".obf.meta", metadataJson, 0666); err != nil {
		panic(err)
	}

}
