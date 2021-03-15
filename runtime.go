package main

import (
	"debug/elf"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"github.com/BlobbyBob/PtraceObfuscator/bin"
	"github.com/BlobbyBob/PtraceObfuscator/common"
	"github.com/BlobbyBob/PtraceObfuscator/ptrace"
	"golang.org/x/arch/x86/x86asm"
	"log"
	"os"
	"syscall"
	"unsafe"
)

// Runtime
//
// The runtime is responsible for restoring the original control flow in the obfuscated binary.
// It has two requirements to run:
//  - The ptrace interface needs to be available (for tracing of children)
//  - A linux kernel version of at least 3.17 for the memfd_create syscall
func main() {
	log.SetOutput(os.Stderr)

	// BEGIN startup phase

	// Deserialize metadata
	metadata, err := readMetadata()
	if err != nil {
		log.Fatalln("can't read metadata:", err)
	}

	// Create in-memory file for obfuscated binary
	obfName := "obf"
	obfFd, _, _ := syscall.Syscall(319, uintptr(unsafe.Pointer(&obfName)), 0, 0) // 319 = memfd_create
	_, _ = syscall.Write(int(obfFd), bin.Obf)
	obfFdPath := fmt.Sprintf("/proc/self/fd/%d", obfFd)

	// Determine .text section offset
	f, err := elf.Open(obfFdPath)
	if err != nil {
		log.Fatalln("can't read binary:", err)
	}
	entrypoint := f.Section(".text").Offset
	_ = f.Close()

	// Start execution with PTRACE_TRACEME
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

	// END of startup phase

	// BEGIN operation phase

	for {
		// Wait for the tracee to pause
		e := <-ev
		status := e.(syscall.WaitStatus)
		if status.Exited() {
			break
		}
		if status.StopSignal() != syscall.SIGTRAP {
			log.Fatalf("unexpected status: %v", status.StopSignal())
		}
		var regs syscall.PtraceRegs
		if err := tracee.GetRegs(&regs); err != nil {
			log.Fatalln("can't read regs:", err)
		}

		// Handler
		if !start {
			// The first "pause" is not a breakpoint, but cause by PTRACE_TRACEME
			// It allows us to prepare the binary with breakpoints
			start = true
			if err := setBreakpoints(tracee, textBaseAddr, metadata); err != nil {
				log.Fatalln("can't set breakpoints:", err)
			}
		} else {
			// All further pauses are caused by a breakpoint
			// Thus, we perform the original instruction as indicated in the metadata
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

// Helper function deserializing the metadata json
func readMetadata() (map[uint64]common.ObfuscatedInstruction, error) {
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

// Helper function setting all the breakpoints in the tracee's memory as indicated by the metadata
func setBreakpoints(tracee *ptrace.Tracee, textBaseAddr uint64, metadata map[uint64]common.ObfuscatedInstruction) error {
	breakpoint := []byte{0xCC}
	for _, inst := range metadata {
		if _, err := tracee.Poke(uintptr(textBaseAddr+inst.Offset), breakpoint); err != nil {
			return err
		}
	}

	return nil
}

// Some flags
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

// Parse flags register into the struct
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

// Search the metadata for the original instruction and perform it manually
func performOriginalInstruction(tracee *ptrace.Tracee, textBaseAddr uint64, metadata map[uint64]common.ObfuscatedInstruction) error {
	// Get registers
	var regs syscall.PtraceRegs
	if err := tracee.GetRegs(&regs); err != nil {
		return err
	}

	offset := regs.Rip - textBaseAddr - 1 // RIP already points to next instruction (after the breakpoint) right now

	// Search metadata
	inst, exists := metadata[offset]
	if exists {
		eflags := parseEflags(regs.Eflags)

		// Check whether we need to jump or not
		var cond bool
		call := false
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
		case x86asm.CALL:
			cond = true
			call = true
			break
		default:
			// We should never land here, as this means, that the Obfuscator replaced an instruction, that we don't know
			log.Fatalln("Unknown instruction:", inst.Inst)
		}

		// Perform the instruction
		return condJump(cond, tracee, regs, inst.Inst, call)
	}

	// ERROR CASE
	//   When we are here, the program stopped at an unknown offset
	//   Uncomment the following lines to print debug information
	//for _, inst := range metadata {
	//	o := 0x200 + inst.Offset - offset
	//	if o < 0x400 {
	//		log.Printf("Offsets not matching: 0x%06x <-> 0x%06x", inst.Offset, offset)
	//	}
	//}
	//log.Printf("RIP: 0x%012x", regs.Rip)
	//mem := make([]byte, 0x40)
	//n, err := tracee.Peek(uintptr(regs.Rip-0x20), mem)
	//if err != nil {
	//	log.Print(n)
	//} else {
	//	for i, b := range mem {
	//		if i >= n {
	//			break
	//		}
	//		fmt.Printf("%02x ", b)
	//	}
	//	fmt.Println()
	//}
	log.Fatal("No matching offset found")
	return nil
}

// Helper function
//   If cond == true, then depending on isCall a jump or call is performed,
//      i.e. the operand of the instruction is evaluated
//   If cond == false, the instruction pointer might still be need to be increased,
//      since the breakpoint has instruction length 1, while the original instruction
//		is most likely a bit longer
func condJump(condition bool, tracee *ptrace.Tracee, regs syscall.PtraceRegs, inst x86asm.Inst, isCall bool) error {
	regs.Rip += uint64(inst.Len - 1)
	if isCall {
		// For a call, we need to push the return address onto the stack
		regs.Rsp -= 8
		returnAddress := make([]byte, 8)
		binary.LittleEndian.PutUint64(returnAddress, regs.Rip)
		if n, err := tracee.Poke(uintptr(regs.Rsp), returnAddress); n != 8 || err != nil {
			return err
		}
	}

	if condition {
		// Consider the different operand types
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
		return dontJump(tracee, regs)
	}
}

// Helper function for the case, that we don't perform the jump
func dontJump(tracee *ptrace.Tracee, regs syscall.PtraceRegs) error {
	return tracee.SetRegs(&regs)
}

// Helper function for performing jumps with register operands
func jumpReg(tracee *ptrace.Tracee, regs syscall.PtraceRegs, reg x86asm.Reg) error {
	val, err := regValue(reg, regs)
	if err != nil {
		log.Fatal("Can't perform indirect register jump: invalid register ", reg.String())
	}
	regs.Rip = val
	return tracee.SetRegs(&regs)
}

// Helper function for performing jumps with memory operands
func jumpMem(tracee *ptrace.Tracee, regs syscall.PtraceRegs, mem x86asm.Mem) error {
	if mem.Segment != 0 {
		// We currently don't support segment registers at all, since they don't seem to be used in x64
		log.Fatal("Can't perform indirect memory jump: segment register not supported; Operand: ", mem.String())
	}
	addr, err := regValue(mem.Base, regs) // Base register
	if err != nil {
		// Register can't be resolved. Should not happen
		log.Fatal("Can't perform indirect memory jump: base register not supported; Operand: ", mem.String())
	}
	addr += uint64(mem.Disp) // Displacement

	if mem.Index != 0 {
		index, err := regValue(mem.Index, regs)
		if err != nil {
			// Register can't be resolved. Should not happen
			log.Fatal("Can't perform indirect memory jump: index register not supported; Operand: ", mem.String())
		}
		addr += index * uint64(mem.Scale) // Scale * Index
	}

	// Dereference pointer
	target := make([]byte, 8)
	if n, err := tracee.Peek(uintptr(addr), target); n != 8 || err != nil {
		log.Fatalf("Can't perform indirect memory jump: can't fetch target address; Operand: %v; n: %v, err: %v", mem.String(), n, err)
	}
	regs.Rip = binary.LittleEndian.Uint64(target)
	return tracee.SetRegs(&regs)
}

// Helper function for performing jumps with immediate operands
func jumpImm(tracee *ptrace.Tracee, regs syscall.PtraceRegs, imm x86asm.Imm) error {
	// Immediate operands don't exist for jumps and calls
	log.Fatal("Can't perform immediate jump")
	return nil
}

// Helper function for performing jumps with relative operands
func jumpRel(tracee *ptrace.Tracee, regs syscall.PtraceRegs, rel x86asm.Rel) error {
	regs.Rip = regs.Rip + uint64(rel)
	return tracee.SetRegs(&regs)
}

// Helper function for translating a x86asm.Reg value to the entry of syscall.PtraceRegs
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
