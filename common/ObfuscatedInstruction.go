package common

import (
	"golang.org/x/arch/x86/x86asm"
)

type ObfuscatedInstruction struct {
	Inst   x86asm.Inst
	Offset uint64
	Binary []byte
}

type ExportObfuscatedInstruction struct {
	Instruction []byte `json:"instruction"`
	Offset uint64 `json:"offset"`
}

func ExportObfuscatedInstructions(input []ObfuscatedInstruction) []ExportObfuscatedInstruction {
	output := make([]ExportObfuscatedInstruction, len(input))
	for i, obfInst := range input {
		output[i].Offset = obfInst.Offset
		output[i].Instruction = obfInst.Binary
	}
	return output
}

func ImportObfuscatedInstructions(input []ExportObfuscatedInstruction) ([]ObfuscatedInstruction, error) {
	output := make([]ObfuscatedInstruction, len(input))
	for i, data := range input {
		output[i].Offset = data.Offset
		output[i].Binary = data.Instruction
		inst, err := x86asm.Decode(data.Instruction, 64)
		if err != nil {
			return nil, err
		}
		output[i].Inst = inst
	}
	return output, nil
}
