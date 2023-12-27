package recorder

import "fmt"

// StackFrame represents a call frame
type StackFrame struct {
	Frame int
	Func  string
	Addr  uint64
}

// String converts to string
func (sf *StackFrame) String() string {
	if sf == nil {
		return "nil"
	}

	name := sf.Func
	if name == "" {
		name = "??"
	}
	return fmt.Sprintf("frame %02d: %s - %016x", sf.Frame, name, sf.Addr)
}
