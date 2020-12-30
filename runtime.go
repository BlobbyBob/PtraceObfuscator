package main

import (
	"debug/elf"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"github.com/BlobbyBob/NOPfuscator/bin"
	"github.com/BlobbyBob/NOPfuscator/common"
	"github.com/BlobbyBob/NOPfuscator/ptrace"
	"golang.org/x/arch/x86/x86asm"
	"log"
	"os"
	"syscall"
	"unsafe"
)

func main() {
	log.SetOutput(os.Stderr)
	//log.Print("Runtime starting")

	//cmd := exec.Command("ls", "-la", fmt.Sprintf("/proc/%v/fd", os.Getpid()))
	//out, _ := cmd.Output()
	//log.Print(string(out))

	metadata, err := readMetadata()
	if err != nil {
		log.Fatalln("can't read metadata:", err)
	}
	_ = len(metadata)

	obfName := "obf"
	obfFd, _, _ := syscall.Syscall(319, uintptr(unsafe.Pointer(&obfName)), 0, 0) // 319 = memfd_create
	_, _ = syscall.Write(int(obfFd), bin.Obf)
	obfFdPath := fmt.Sprintf("/proc/self/fd/%d", obfFd)

	f, err := elf.Open(obfFdPath)
	if err != nil {
		log.Fatalln("can't read binary:", err)
	}
	entrypoint := f.Section(".text").Offset
	_ = f.Close()

	tracee, err := ptrace.Exec(obfFdPath, os.Args)
	if err != nil {
		log.Fatalln("can't exec binary:", err)
	}

	ev := tracee.Events()
	start := false

	// Find start of .text section
	// This method might not work if you manually change your segments and sections in some strange ways
	execSection, _ := tracee.FirstExecSection()
	textBaseAddr := execSection.StartAddr + entrypoint - execSection.Offset

	for {
		e := <-ev
		status := e.(syscall.WaitStatus)
		if status.Exited() {
			break
		}
		var regs syscall.PtraceRegs
		if err := tracee.GetRegs(&regs); err != nil {
			log.Fatalln("can't read regs:", err)
		}
		if !start {
			start = true
			log.Printf(".text at 0x%012x\n", textBaseAddr)
			log.Printf("Start at 0x%012x\n", regs.Rip)
			if err := setBreakpoints(tracee, textBaseAddr, metadata); err != nil {
				log.Fatalln("can't set breakpoints:", err)
			}

			log.Print("Contents of .text:")
			buf := make([]byte, 0x80)
			if _, err := tracee.Peek(uintptr(textBaseAddr), buf); err != nil {
				log.Fatalln(err)
			}
			for _, b := range buf {
				fmt.Printf("%02x ", b)
			}
			fmt.Println()
		} else {
			//log.Printf("0x%012x: Breakpoint (offset %012x)\n", regs.Rip, regs.Rip-textBaseAddr)
			if err := performOriginalInstruction(tracee, textBaseAddr, metadata); err != nil {
				log.Fatalln("can't perform original instruction:", err)
			}
		}
		if err := tracee.Continue(); err != nil {
			log.Fatalln("can't continue tracee:", err)
		}
	}

	if err := tracee.Close(); err != nil {
		log.Fatalln("can't close tracee:", err)
	}

}

func readMetadata() ([]common.ObfuscatedInstruction, error) {
	var metadataRaw []common.ExportObfuscatedInstruction
	if err := json.Unmarshal(bin.Meta, &metadataRaw); err != nil {
		return nil, err
	}

	m, err := common.ImportObfuscatedInstructions(metadataRaw)
	if err != nil {
		return nil, err
	}

	return m, nil
}

func setBreakpoints(tracee *ptrace.Tracee, textBaseAddr uint64, metadata []common.ObfuscatedInstruction) error {
	breakpoint := []byte{0xCC}
	//original := make([]byte, 1)
	for _, inst := range metadata {
		//if _, err := tracee.Peek(uintptr(textBaseAddr+inst.Offset), original); err != nil {
		//	return err
		//}
		if _, err := tracee.Poke(uintptr(textBaseAddr+inst.Offset), breakpoint); err != nil {
			return err
		}
		//log.Printf("0x%012x: replaced 0x%02x with 0x%02x\n", textBaseAddr+inst.Offset, original[0], breakpoint[0])
	}

	return nil
}

type Eflags struct {
	CF bool
	PF bool
	AF bool
	ZF bool
	SF bool
	TF bool
	IF bool
	DF bool
	OF bool
}

func parseEflags(flags uint64) Eflags {
	return Eflags{
		CF: flags&0x1 != 0,
		PF: flags&0x4 != 0,
		AF: flags&0x10 != 0,
		ZF: flags&0x40 != 0,
		SF: flags&0x80 != 0,
		TF: flags&0x100 != 0,
		IF: flags&0x200 != 0,
		DF: flags&0x400 != 0,
		OF: flags&0x800 != 0,
	}
}

func performOriginalInstruction(tracee *ptrace.Tracee, textBaseAddr uint64, metadata []common.ObfuscatedInstruction) error {
	var regs syscall.PtraceRegs
	if err := tracee.GetRegs(&regs); err != nil {
		return err
	}

	// Todo be more efficient in searching metadata

	offset := regs.Rip - textBaseAddr - 1 // RIP already points to next instruction right now

	for _, inst := range metadata {
		if inst.Offset == offset {
			eflags := parseEflags(regs.Eflags)

			var cond bool
			switch inst.Inst.Op {
			case x86asm.JMP:
				cond = true
				break
			case x86asm.JO:
				cond = eflags.OF
				break
			case x86asm.JNO:
				cond = !eflags.OF
				break
			case x86asm.JS:
				cond = eflags.SF
				break
			case x86asm.JNS:
				cond = !eflags.SF
				break
			case x86asm.JE:
				cond = eflags.ZF
				break
			case x86asm.JNE:
				cond = !eflags.ZF
				break
			case x86asm.JB:
				cond = eflags.CF
				break
			case x86asm.JAE:
				cond = !eflags.CF
				break
			case x86asm.JBE:
				cond = eflags.CF || eflags.ZF
				break
			case x86asm.JA:
				cond = !eflags.CF && !eflags.ZF
				break
			case x86asm.JL:
				cond = eflags.SF != eflags.OF
				break
			case x86asm.JGE:
				cond = eflags.SF == eflags.OF
				break
			case x86asm.JLE:
				cond = eflags.ZF || eflags.SF != eflags.OF
				break
			case x86asm.JG:
				cond = !eflags.ZF && eflags.SF == eflags.OF
				break
			case x86asm.JP:
				cond = eflags.PF
				break
			case x86asm.JNP:
				cond = !eflags.PF
				break
			case x86asm.JRCXZ:
				cond = regs.Rcx == 0
				break
			case x86asm.JECXZ:
				cond = regs.Rcx&0xffffffff == 0
				break
			case x86asm.JCXZ:
				cond = regs.Rcx&0xffff == 0
				break
			default:
				log.Fatalln("Unknown instruction:", inst.Inst)
			}

			return condJump(cond, tracee, regs, inst.Inst)
		}
	}
	for _, inst := range metadata {

		log.Printf("Offsets not matching: 0x%06x <-> 0x%06x", inst.Offset, offset)
	}
	mem := make([]byte, 0x40)
	n, err := tracee.Peek(uintptr(regs.Rip-0x20), mem)
	if err != nil {
		log.Print(n)
	} else {
		for i, b := range mem {
			if i >= n {
				break
			}
			fmt.Printf("%02x ", b)
		}
		fmt.Println()
	}
	log.Fatal("No matching offset found")
	return nil
}

func condJump(condition bool, tracee *ptrace.Tracee, regs syscall.PtraceRegs, inst x86asm.Inst) error {
	regs.Rip += uint64(inst.Len - 1)
	if condition {
		arg := inst.Args[0]
		if rel, isRel := arg.(x86asm.Rel); isRel {
			return jumpRel(tracee, regs, rel)
		} else if imm, isImm := arg.(x86asm.Imm); isImm {
			return jumpImm(tracee, regs, imm)
		} else if mem, isMem := arg.(x86asm.Mem); isMem {
			return jumpMem(tracee, regs, mem)
		} else if reg, isReg := arg.(x86asm.Reg); isReg {
			return jumpReg(tracee, regs, reg)
		} else {
			return fmt.Errorf("can't decode argument of instruction %v", inst)
		}
	} else {
		//log.Printf("0x%012x: Don't jump (%v)\n", regs.Rip, inst)
		return dontJump(tracee, regs)
	}
}

func dontJump(tracee *ptrace.Tracee, regs syscall.PtraceRegs) error {
	return tracee.SetRegs(&regs)
}

func jumpReg(tracee *ptrace.Tracee, regs syscall.PtraceRegs, reg x86asm.Reg) error {
	val, err := regValue(reg, regs)
	if err != nil {
		log.Fatal("Can't perform indirect register jump: invalid register ", reg.String())
	}
	regs.Rip = val
	return tracee.SetRegs(&regs)
}

func jumpMem(tracee *ptrace.Tracee, regs syscall.PtraceRegs, mem x86asm.Mem) error {
	if mem.Segment != 0 {
		log.Fatal("Can't perform indirect memory jump: segment register not supported; Operand: ", mem.String())
	}
	addr, err := regValue(mem.Base, regs)
	if err != nil {
		log.Fatal("Can't perform indirect memory jump: base register not supported; Operand: ", mem.String())
	}
	addr += uint64(mem.Disp)

	if mem.Index != 0 {
		index, err := regValue(mem.Index, regs)
		if err != nil {
			log.Fatal("Can't perform indirect memory jump: index register not supported; Operand: ", mem.String())
		}
		addr += index * uint64(mem.Scale)
	}
	target := make([]byte, 8)
	if n, err := tracee.Peek(uintptr(addr), target); n != 8 || err != nil {
		log.Fatalf("Can't perform indirect memory jump: can't fetch target address; Operand: %v; n: %v, err: %v", mem.String(), n, err)
	}
	regs.Rip = binary.LittleEndian.Uint64(target)
	return tracee.SetRegs(&regs)
}

func jumpImm(tracee *ptrace.Tracee, regs syscall.PtraceRegs, imm x86asm.Imm) error {
	// todo (However, I don't think this exists)
	log.Fatal("Can't perform immediate jump")
	return tracee.SetRegs(&regs)
}

func jumpRel(tracee *ptrace.Tracee, regs syscall.PtraceRegs, rel x86asm.Rel) error {
	regs.Rip = regs.Rip + uint64(rel)
	return tracee.SetRegs(&regs)
}

func regValue(reg x86asm.Reg, regs syscall.PtraceRegs) (uint64, error) {
	var val uint64
	switch reg {
	case x86asm.RAX:
		val = regs.Rax
		break
	case x86asm.RBX:
		val = regs.Rbx
		break
	case x86asm.RCX:
		val = regs.Rcx
		break
	case x86asm.RDX:
		val = regs.Rdx
		break
	case x86asm.RSP:
		val = regs.Rsp
		break
	case x86asm.RBP:
		val = regs.Rbp
		break
	case x86asm.RIP:
		val = regs.Rip
		break
	case x86asm.RDI:
		val = regs.Rdi
		break
	case x86asm.RSI:
		val = regs.Rsi
		break
	case x86asm.R8:
		val = regs.R8
		break
	case x86asm.R9:
		val = regs.R9
		break
	case x86asm.R10:
		val = regs.R10
		break
	case x86asm.R11:
		val = regs.R11
		break
	case x86asm.R12:
		val = regs.R12
		break
	case x86asm.R13:
		val = regs.R13
		break
	case x86asm.R14:
		val = regs.R14
		break
	case x86asm.R15:
		val = regs.R15
		break
	default:
		return val, fmt.Errorf("invalid register: %v", reg)
	}
	return val, nil
}
