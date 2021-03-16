# PtraceObfuscator

An x86-64 ELF obfuscator based on hiding the control flow using the ptrace interface.
An advanced description is available in the [paper](paper.pdf) in this repo.

## How to use

Consult [golang.org](https://golang.org/doc/) for information on how to set up Go.

Example usage:
```
git clone git@github.com:BlobbyBob/PtraceObfuscator.git
cd PtraceObfuscator
go mod download
go build packer.go
cp $(which du) .
./packer -f du
./du.packed -hs ~
```

You can use the `-nop` option if you want the obfuscated instructions to be replaced with NOPs instead of random data. 

## Limitations

There are some conditions that the input binary needs to fulfill:
- It needs to be linearly disassemblable
- It needs to be single-threaded (and may only use a single process)

As these are implementable in theory, feel free to create a pull request, if you want to improve the PtraceObfuscator.
