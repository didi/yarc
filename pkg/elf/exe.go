// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package elf

import (
	"bytes"
	"debug/elf"
	"errors"
	"io"
	"os"
)

type exeFile interface {
	Close()
	Symbol(name string) uint64
	DataStart() uint64
	ReadData(addr, n uint64) ([]byte, error)
}

type elfFile struct {
	f *os.File
	e *elf.File
}

func (x *elfFile) Close() {
	if x.f != nil {
		x.f.Close()
	}
	if x.e != nil {
		x.e.Close()
	}
}

func (x *elfFile) Symbol(name string) uint64 {
	symbols, err := x.e.Symbols()
	if err != nil {
		return 0
	}
	dsymbols, err := x.e.DynamicSymbols()
	if err != nil {
		return 0
	}
	symbols = append(symbols, dsymbols...)
	for _, symbol := range symbols {
		if symbol.Name != name {
			continue
		}
		off := symbol.Value
		// Loop over ELF segments.
		for _, prog := range x.e.Progs {
			// Skip uninteresting segments.
			if prog.Type != elf.PT_LOAD || (prog.Flags&elf.PF_X) == 0 {
				continue
			}

			if prog.Vaddr <= symbol.Value && symbol.Value < (prog.Vaddr+prog.Memsz) {
				// If the symbol value is contained in the segment, calculate
				// the symbol offset.
				//
				// fn symbol offset = fn symbol VA - .text VA + .text offset
				//
				// stackoverflow.com/a/40249502
				off = symbol.Value - prog.Vaddr + prog.Off
				break
			}
		}
		return off
	}
	return 0
}

func (x *elfFile) DataStart() uint64 {
	for _, s := range x.e.Sections {
		if s.Name == ".go.buildinfo" {
			return s.Addr
		}
	}

	for _, p := range x.e.Progs {
		if p.Type == elf.PT_LOAD && p.Flags&(elf.PF_X|elf.PF_W) == elf.PF_W {
			return p.Vaddr
		}
	}

	return 0
}

func (x *elfFile) ReadData(addr, n uint64) ([]byte, error) {
	for _, prog := range x.e.Progs {
		if prog.Vaddr <= addr && prog.Vaddr+prog.Filesz > addr {
			if n > prog.Filesz-(addr-prog.Vaddr) {
				n = prog.Filesz - (addr - prog.Vaddr)
			}
			data := make([]byte, n)
			_, err := prog.ReadAt(data, int64(addr-prog.Vaddr))
			if err != nil {
				return nil, err
			}
			return data, nil
		}
	}
	return nil, errors.New("address not mapped")
}

func openExe(name string) (exeFile, error) {
	f, err := os.OpenFile(name, os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}

	_, err = f.Seek(0, io.SeekStart)
	if err != nil {
		return nil, err
	}

	buf := make([]byte, 16)
	_, err = io.ReadFull(f, buf)
	if err != nil {
		f.Close()
		return nil, err
	}

	if bytes.HasPrefix(buf, []byte("\x7FELF")) {
		e, err := elf.Open(name)
		if err != nil {
			f.Close()
			return nil, err
		}
		return &elfFile{f: f, e: e}, nil
	}

	f.Close()
	return nil, errors.New("unrecognized executable format")
}
