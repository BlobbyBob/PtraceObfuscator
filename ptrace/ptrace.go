// Package ptrace provides an interface to the ptrace system call.
// Fork of: github.com/eaburns/ptrace
package ptrace

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
)

var (
	// ErrExited is returned when a command is executed on a tracee
	// that has already exited.
	ErrExited = errors.New("tracee exited")
)

// An Event is sent on a Tracee's event channel whenever it changes state.
type Event interface{}

// A Tracee is a process that is being traced.
type Tracee struct {
	proc   *os.Process
	events chan Event
	err    chan error

	cmds chan func()
}

type SectionInfo struct {
	StartAddr uint64
	EndAddr uint64
	Flags uint8
	Offset uint64
	Device string
	Inode string
	Name string
}

// Events returns the events channel for the tracee.
func (t *Tracee) Events() <-chan Event {
	return t.events
}

// Exec executes a process with tracing enabled, returning the Tracee
// or an error if an error occurs while executing the process.
func Exec(name string, argv []string) (*Tracee, error) {
	t := &Tracee{
		events: make(chan Event, 1),
		err:    make(chan error, 1),
		cmds:   make(chan func()),
	}

	err := make(chan error)
	proc := make(chan *os.Process)
	go func() {
		runtime.LockOSThread()
		p, e := os.StartProcess(name, argv, &os.ProcAttr{
			Files: []*os.File{os.Stdin, os.Stdout, os.Stderr},
			Sys: &syscall.SysProcAttr{
				Ptrace:    true,
				Pdeathsig: syscall.SIGCHLD,
			},
		})
		proc <- p
		err <- e
		if e != nil {
			return
		}
		go t.wait()
		t.trace()
	}()
	t.proc = <-proc
	return t, <-err
}

// Detach detaches the tracee, allowing it to continue its execution normally.
// No more tracing is performed, and no events are sent on the event channel
// until the tracee exits.
func (t *Tracee) Detach() error {
	err := make(chan error, 1)
	if t.do(func() { err <- syscall.PtraceDetach(t.proc.Pid) }) {
		return <-err
	}
	return ErrExited
}

// SingleStep continues the tracee for one instruction.
func (t *Tracee) SingleStep() error {
	err := make(chan error, 1)
	if t.do(func() { err <- syscall.PtraceSingleStep(t.proc.Pid) }) {
		return <-err
	}
	return ErrExited
}

// Continue makes the tracee execute unmanaged by the tracer.  Most
// commands are not possible in this state, with the notable exception
// of sending a syscall.SIGSTOP signal.
func (t *Tracee) Continue() error {
	err := make(chan error, 1)
	const signum = 0
	if t.do(func() { err <- syscall.PtraceCont(t.proc.Pid, signum) }) {
		return <-err
	}
	return ErrExited
}

// Kill sends the given signal to the tracee.
func (t *Tracee) Kill(sig syscall.Signal) error {
	err := make(chan error, 1)
	if t.do(func() { err <- syscall.Kill(t.proc.Pid, sig) }) {
		return <-err
	}
	return ErrExited
}

// Sends the command to the tracer go routine.  Returns whether the command
// was sent or not.  The command may not have been sent if the tracee exited.
func (t *Tracee) do(f func()) bool {
	if t.cmds != nil {
		t.cmds <- f
		return true
	}
	return false
}

// Close cleans up internal memory for managing the tracee.  If an error is
// pending, it is returned.
func (t *Tracee) Close() error {
	var err error
	select {
	case err = <-t.err:
	default:
		err = nil
	}
	close(t.err)
	close(t.cmds)
	t.cmds = nil
	return err
}

func (t *Tracee) wait() {
	defer close(t.events)
	for {
		state, err := t.proc.Wait()
		if err != nil {
			t.err <- err
			return
		}
		if state.Exited() {
			t.events <- Event(state.Sys().(syscall.WaitStatus))
			return
		}
		t.events <- Event(state.Sys().(syscall.WaitStatus))
	}
}

func (t *Tracee) trace() {
	for cmd := range t.cmds {
		cmd()
	}
}

func (t *Tracee) GetRegs(regs *syscall.PtraceRegs) error {
	err := make(chan error, 1)
	if t.do(func() { err <- syscall.PtraceGetRegs(t.proc.Pid, regs) }) {
		return <-err
	}
	return ErrExited
}

func (t *Tracee) SetRegs(regs *syscall.PtraceRegs) error {
	err := make(chan error, 1)
	if t.do(func() { err <- syscall.PtraceSetRegs(t.proc.Pid, regs) }) {
		return <-err
	}
	return ErrExited
}

func (t *Tracee) Peek(addr uintptr, data []byte) (int, error) {
	err := make(chan error, 1)
	count := make(chan int, 1)
	if t.do(func() { c, e := syscall.PtracePeekText(t.proc.Pid, addr, data); count <- c; err <- e }) {
		return <-count, <-err
	}
	return 0, ErrExited
}

func (t *Tracee) Poke(addr uintptr, data []byte) (int, error) {
	err := make(chan error, 1)
	count := make(chan int, 1)
	if t.do(func() { c, e := syscall.PtracePokeText(t.proc.Pid, addr, data); count <- c; err <- e }) {
		return <-count, <-err
	}
	return 0, ErrExited
}

func (t *Tracee) Memmap() ([]byte, error) {
	return ioutil.ReadFile(fmt.Sprintf("/proc/%v/maps", t.proc.Pid))
}

func (t *Tracee) FirstExecSection() (*SectionInfo, error) {
	memmap, err := t.Memmap()
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(memmap), "\n")
	for _, line := range lines {
		if strings.Contains(line, "x") {
			parts := strings.Split(line, " ")
			if len(parts) >= 2 && parts[1][2] == 'x' {
				return parseSectionInfo(parts), nil
			}
		}
	}
	return nil, fmt.Errorf("no executable section found")
}

func parseSectionInfo(parts []string) *SectionInfo {
	si := new(SectionInfo)
	i := 0
	for _, p := range parts {
		name := strings.Builder{}
		if len(p) == 0 && name.Len() == 0 {
			continue
		}
		switch i {
		case 0:
			addresses := strings.Split(p, "-")
			si.StartAddr, _ = strconv.ParseUint(addresses[0], 16, 64)
			si.EndAddr, _ = strconv.ParseUint(addresses[1], 16, 64)
			si.EndAddr--
			i++
			break
		case 1:
			si.Flags = 0
			if strings.Contains(p, "r") {
				si.Flags |= 1 << 0
			}
			if strings.Contains(p, "w") {
				si.Flags |= 1 << 1
			}
			if strings.Contains(p, "x") {
				si.Flags |= 1 << 2
			}
			if strings.Contains(p, "p") {
				si.Flags |= 1 << 3
			}
			if strings.Contains(p, "s") {
				si.Flags |= 1 << 4
			}
			i++
			break
		case 2:
			si.Offset, _ = strconv.ParseUint(p, 16, 64)
			i++
			break
		case 3:
			si.Device = p
			i++
			break
		case 4:
			si.Inode = p
			i++
			break
		case 5:
			if name.Len() > 0 {
				name.WriteByte(' ')
			}
			name.WriteString(p)
			break
		}
		si.Name = name.String()
	}
	return si
}