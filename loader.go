package main

import (
	"fmt"
	"github.com/BlobbyBob/NOPfuscator/loader"
	"log"
	"os"
	"syscall"
	"unsafe"
)

const (
	SYS_MEMFD_CREATE = 319
	MFD_CLOEXEC      = 1
)

func main() {
	log.Print("Loading started")

	metaName := "meta"
	metaFd, _, _ := syscall.Syscall(SYS_MEMFD_CREATE, uintptr(unsafe.Pointer(&metaName)), 0, 0)
	_, _ = syscall.Write(int(metaFd), loader.Meta)
	log.Print("meta fd ", metaFd)

	obfName := "obf"
	obfFd, _, _ := syscall.Syscall(SYS_MEMFD_CREATE, uintptr(unsafe.Pointer(&obfName)), 0, 0)
	_, _ = syscall.Write(int(obfFd), loader.Obf)
	log.Print("obf fd ", obfFd)

	runtimeName := "runtime"
	runtimeFd, _, _ := syscall.Syscall(SYS_MEMFD_CREATE, uintptr(unsafe.Pointer(&runtimeName)), uintptr(MFD_CLOEXEC), 0)
	_, _ = syscall.Write(int(runtimeFd), loader.Runtime)
	runtimeFdPath := fmt.Sprintf("/proc/self/fd/%d", runtimeFd)
	log.Print("runtime fd ", runtimeFd)

	log.Print("Loaded successfully")

	_ = syscall.Exec(runtimeFdPath, os.Args, os.Environ())
}
