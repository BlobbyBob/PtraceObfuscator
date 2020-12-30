package obfuscator

import (
	"debug/elf"
	"github.com/BlobbyBob/NOPfuscator/common"
	"golang.org/x/arch/x86/x86asm"
	"io/ioutil"
	"log"
)

func Obfuscate(filename string) (obfElf []byte, obfInst *[]common.ObfuscatedInstruction, err error) {
	file, err := elf.Open(filename)
	if err != nil {
		return nil, nil, err
	}

	textSection := file.Section(".text")
	textReader := textSection.Open()
	code := make([]byte, 0)
	for {
		codeBit := make([]byte, 8)
		n, err := textReader.Read(codeBit)
		if err != nil {
			break
		}
		code = append(code, codeBit[:n]...)
	}

	err = nil
	i := 0
	obfuscatedInstructions := make([]common.ObfuscatedInstruction, 0)
	for i < len(code) {
		// Dirty hack to catch unknown instruction endbr64
		if len(code)-i >= 4 {
			endbr64 := [4]byte{0xf3, 0x0f, 0x1e, 0xfa}
			var testForEndbr64 [4]byte
			copy(testForEndbr64[:], code[i:i+4])
			if endbr64 == testForEndbr64 {
				//log.Printf("offset 0x%x: Skipping endbr64\n", i)
				i += 4
				continue
			}
		}
		// Circumventing issues, when an instruction gets decoded as prefix

		var inst x86asm.Inst
		inst, err = x86asm.Decode(code[i:], 64)
		if err != nil {
			// If we are strict we return an error here
			// However, we will use the soft version and just skip obfuscating, if we can't decode an instruction
			log.Printf("Can't decode instruction at offset %v: %v\n", i, err)
			log.Printf("Bytes: %x\n", code[i:i+8])
			break
		}

		if inst.Opcode == 0 && inst.Prefix[0] != 0 {
			log.Printf("offset 0x%x: warn: encountered instruction '%v', which is most likely decoded incorrectly. stopping here\n", uint64(i)+textSection.Offset, inst)
			break
		}

		// Find instructions to obfuscate
		if obfuscateInstruction(inst) {
			obfuscatedInstructions = append(obfuscatedInstructions, common.ObfuscatedInstruction{
				Inst:   inst,
				Offset: uint64(i),
				Binary: code[i : i+inst.Len],
			})
		}
		i += inst.Len
	}

	log.Printf("Obfuscated %d instructions", len(obfuscatedInstructions))

	elfContents, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, nil, err
	}

	obfuscatedElf := make([]byte, len(elfContents))

	for offset, data := range elfContents {
		// Obfuscate matched instructions in text section
		if uint64(offset) >= textSection.Offset && uint64(offset) < textSection.Offset+textSection.Size {
			relOffset := uint64(offset) - textSection.Offset
			isJump := false
			for _, jump := range obfuscatedInstructions {
				if relOffset >= jump.Offset && relOffset < jump.Offset+uint64(jump.Inst.Len) {
					isJump = true
				}
			}
			if isJump {
				obfuscatedElf[offset] = 0x90 // todo Wouldn't it be even better to use random bytes in here?
			} else {
				obfuscatedElf[offset] = data
			}
		} else {
			obfuscatedElf[offset] = data
		}
	}

	return obfuscatedElf, &obfuscatedInstructions, nil
}

func obfuscateInstruction(inst x86asm.Inst) bool {
	switch inst.Op {
	case x86asm.JA,
		x86asm.JAE,
		x86asm.JB,
		x86asm.JBE,
		x86asm.JCXZ,
		x86asm.JE,
		x86asm.JECXZ,
		x86asm.JG,
		x86asm.JGE,
		x86asm.JL,
		x86asm.JLE,
		x86asm.JMP,
		x86asm.JNE,
		x86asm.JNO,
		x86asm.JNP,
		x86asm.JNS,
		x86asm.JO,
		x86asm.JP,
		x86asm.JRCXZ,
		x86asm.JS:
		return true
	}

	return false
}
