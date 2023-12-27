package kallsyms

import (
	"bufio"
	"errors"
	"os"
	"sort"
	"strconv"
	"strings"
)

// KAllSymbols saves all symbols in kernel.
type KAllSymbols struct {
	symbols []*KSymbol
}

// KSymbol represents a symbol in kernel.
type KSymbol struct {
	Type KSymbolType
	Addr uint64
	Size uint32
	Name string
}

var kallsyms KAllSymbols

func init() {
	kallsyms.symbols, _ = LoadKallsyms()
	sort.Sort(&kallsyms)
}

// Lookup finds the symbol by memory address.
func Lookup(addr uint64) *KSymbol {
	return kallsyms.Lookup(addr)
}

// LoadKallsyms loads all symbols from /proc/kallsyms.
func LoadKallsyms() ([]*KSymbol, error) {
	file, err := os.OpenFile("/proc/kallsyms", os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}

	scanner := bufio.NewScanner(file)
	syms := []*KSymbol{}
	for scanner.Scan() {
		text := scanner.Text()
		sym := &KSymbol{}
		err := sym.parse(text)
		if err != nil {
			return nil, err
		}
		syms = append(syms, sym)
	}
	return syms, nil
}

func (ks *KSymbol) parse(text string) error {
	fields := strings.Split(text, " ")
	if len(fields) < 3 {
		return errors.New("fiele num error")
	}

	var err error
	ks.Addr, err = strconv.ParseUint(fields[0], 16, 64)
	if err != nil {
		return errors.New("addr format error")
	}

	ks.Type = parseSymbolType(fields[1])
	ks.Name = fields[2]
	return nil
}

// Len return the count of kernel symbols.
func (ks *KAllSymbols) Len() int {
	return len(ks.symbols)
}

// Less compares the addresses of symbols with subscripts i and j.
func (ks *KAllSymbols) Less(i, j int) bool {
	return ks.symbols[i].Addr < ks.symbols[j].Addr
}

// Swap swaps symbols with subscripts i and j.
func (ks *KAllSymbols) Swap(i, j int) {
	sym := ks.symbols[i]
	ks.symbols[i] = ks.symbols[j]
	ks.symbols[j] = sym
}

// Lookup finds symbol by memory address.
func (ks *KAllSymbols) Lookup(addr uint64) *KSymbol {
	len := len(ks.symbols)
	for i, sym := range ks.symbols {
		if sym.Addr > addr {
			break
		}

		if i+1 >= len || ks.symbols[i+1].Addr > addr {
			return sym
		}
	}
	return nil
}
