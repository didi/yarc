package elf

// SymbolOffset parses the binary file with the specified path
// and gets the offset of the symbol with the specified name.
func SymbolOffset(path, name string) (uint64, error) {
	ex, err := openExe(path)
	if err != nil {
		return 0, err
	}
	defer ex.Close()
	return ex.Symbol(name), nil
}
