# PtraceObfuscator

An x86-64 ELF obfuscator based on hiding the control flow using the ptrace interface.

## How to use

Consult [golang.org](https://golang.org/doc/) for information on how to set up Go.

Example usage:
```
git clone git@github.com:BlobbyBob/PtraceObfuscator.git
go mod download
go build packer.go
cp $(which du) .
./packer -f du
./du.packed -hs ~
```

You can use the `-nop` option if you want the obfuscated instructions to be replaced with NOPs instead of random data. 



