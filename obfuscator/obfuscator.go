package obfuscator

import (
	"debug/elf"
	"fmt"
	"golang.org/x/arch/x86/x86asm"
	"io/ioutil"
)

type Jump struct {
	Inst   x86asm.Inst
	Offset uint64
}

func Obfuscate(filename string) error {
	file, err := elf.Open(filename)
	if err != nil {
		return err
	}

	fmt.Println("ELF Type:", file.Type)

	textSection := file.Section(".text")
	fmt.Println("Section Name:", textSection.Name)

	textReader := textSection.Open()
	var code []byte
	for {
		codeBit := []byte{0, 0, 0, 0, 0, 0, 0, 0}
		_, err := textReader.Read(codeBit)
		if err != nil {
			break
		}
		code = append(code, codeBit...)
		//fmt.Println(hex.EncodeToString(codeBit))
	}

	fmt.Println()

	err = nil
	i := 0
	jumps := []Jump{}
	for i < len(code) {
		var inst x86asm.Inst
		inst, err = x86asm.Decode(code[i:], 64)
		if err != nil {
			return err
		}

		if inst.Op.String()[0] == 'J' {
			jumps = append(jumps, Jump{
				Inst:   inst,
				Offset: uint64(i),
			})
		}
		fmt.Printf("[%03x|%01x]    ", i, inst.Len)
		s := ""
		for _, c := range code[i : i+inst.Len] {
			s += fmt.Sprintf("%02x ", c)
		}
		fmt.Printf("%-21v", s)
		fmt.Println(inst.String())
		i += inst.Len
	}

	// Find start of .text
	elfContents, err := ioutil.ReadFile(filename)
	if err != nil {
		return err
	}

	var obfuscatedElf []byte

	for offset, data := range elfContents {
		if uint64(offset) >= textSection.Offset && uint64(offset) < textSection.Offset+textSection.Size {
			relOffset := uint64(offset) - textSection.Offset
			isJump := false
			for _, jump := range jumps {
				if relOffset >= jump.Offset && relOffset < jump.Offset+uint64(jump.Inst.Len) {
					isJump = true
				}
			}
			if isJump {
				obfuscatedElf = append(obfuscatedElf, 0x90)
			} else {
				obfuscatedElf = append(obfuscatedElf, data)
			}
		} else {
			obfuscatedElf = append(obfuscatedElf, data)
		}
	}

	err = ioutil.WriteFile(filename+".obf", obfuscatedElf, 0666)
	if err != nil {
		return err
	}
	return nil
}
