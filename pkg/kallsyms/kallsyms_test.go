package kallsyms

import (
	"testing"
)

func TestLoadKallsyms(t *testing.T) {
	syms, err := LoadKallsyms()
	if err != nil {
		t.Log(err)
		t.Fail()
	}

	t.Log(syms[0])
}
