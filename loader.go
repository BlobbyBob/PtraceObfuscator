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
	metaName := "meta"
	metaFd, _, _ := syscall.Syscall(SYS_MEMFD_CREATE, uintptr(unsafe.Pointer(&metaName)), uintptr(MFD_CLOEXEC), 0)
	_, _ = syscall.Write(int(metaFd), loader.Meta)
	metaFdPath := fmt.Sprintf("/proc/self/fd/%d", metaFd)

	obfName := "obf"
	obfFd, _, _ := syscall.Syscall(SYS_MEMFD_CREATE, uintptr(unsafe.Pointer(&obfName)), uintptr(MFD_CLOEXEC), 0)
	_, _ = syscall.Write(int(obfFd), loader.Obf)
	obfFdPath := fmt.Sprintf("/proc/self/fd/%d", obfFd)

	runtimeName := "runtime"
	runtimeFd, _, _ := syscall.Syscall(SYS_MEMFD_CREATE, uintptr(unsafe.Pointer(&runtimeName)), uintptr(MFD_CLOEXEC), 0)
	_, _ = syscall.Write(int(runtimeFd), loader.Runtime)
	runtimeFdPath := fmt.Sprintf("/proc/self/fd/%d", runtimeFd)

	log.Print("Loaded successfully")

	_ = syscall.Exec(runtimeFdPath, []string{"obfuscatedBinary", obfFdPath, metaFdPath}, os.Environ())
}
