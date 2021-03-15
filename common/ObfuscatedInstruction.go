package common

import (
	"golang.org/x/arch/x86/x86asm"
)

// Internal metadata contains the decoded instruction
type ObfuscatedInstruction struct {
	Inst   x86asm.Inst
	Offset uint64
	Binary []byte
}

// External metadata only contains the instruction bytes and the offset
type ExportObfuscatedInstruction struct {
	Instruction []byte `json:"instruction"`
	Offset uint64 `json:"offset"`
}

// Utility function
// Conversion from internal metadata to external metadata
func ExportObfuscatedInstructions(input []ObfuscatedInstruction) []ExportObfuscatedInstruction {
	output := make([]ExportObfuscatedInstruction, len(input))
	for i, obfInst := range input {
		output[i].Offset = obfInst.Offset
		output[i].Instruction = obfInst.Binary
	}
	return output
}

// Utility function
// Conversion from external metadata to internal metadata
func ImportObfuscatedInstructions(input []ExportObfuscatedInstruction) (map[uint64]ObfuscatedInstruction, error) {
	output := make(map[uint64]ObfuscatedInstruction, len(input))
	for _, data := range input {
		inst, err := x86asm.Decode(data.Instruction, 64)
		if err != nil {
			return nil, err
		}
		output[data.Offset] = ObfuscatedInstruction{
			Offset: data.Offset,
			Binary: data.Instruction,
			Inst: inst,
		}
	}
	return output, nil
}
