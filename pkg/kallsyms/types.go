package kallsyms

// KSymbolType kernel symbol type
type KSymbolType int

const (
	// Unknown unknown type
	Unknown KSymbolType = iota
	// Absolute absolute
	Absolute
	// UninitializedData uninitialized data
	UninitializedData
	// CommonSymbol common symbol
	CommonSymbol
	// InitializedData initialized data
	InitializedData
	// GlobalInitializedData global initialized data
	GlobalInitializedData
	// IndirectFunction indirect function
	IndirectFunction
	// IndirectReference indirect reference
	IndirectReference
	// DebugingSymbol debuging symbol
	DebugingSymbol
	// StackUnwindSection stack unwind section
	StackUnwindSection
	// ReadOnlyData read only data
	ReadOnlyData
	// UninitializedSmallData uninitialized small data
	UninitializedSmallData
	// TextSectionSymbol text section symbol
	TextSectionSymbol
	// Undefined undefined
	Undefined
	// UniqueGlobalSymbol unique global symbol
	UniqueGlobalSymbol
	// WeakObject weak object
	WeakObject
	// WeakObjectUnspecifically weak object unspecifically
	WeakObjectUnspecifically
	// StabsSymbol stabs symbol
	StabsSymbol
)

func parseSymbolType(str string) KSymbolType {
	if len(str) <= 0 {
		return Unknown
	}

	switch str[0] {
	case 'A':
		return Absolute
	case 'B', 'b':
		return UninitializedData
	case 'C':
		return CommonSymbol
	case 'D', 'd':
		return InitializedData
	case 'G', 'g':
		return GlobalInitializedData
	case 'i':
		return IndirectFunction
	case 'I':
		return IndirectReference
	case 'N', 'n':
		return DebugingSymbol
	case 'p':
		return StackUnwindSection
	case 'R', 'r':
		return ReadOnlyData
	case 'S', 's':
		return UninitializedSmallData
	case 'T', 't':
		return TextSectionSymbol
	case 'U':
		return Undefined
	case 'u':
		return UniqueGlobalSymbol
	case 'V', 'v':
		return WeakObject
	case 'W', 'w':
		return WeakObjectUnspecifically
	case '-':
		return StabsSymbol
	case '?':
	default:
	}
	return Unknown
}
