// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package elf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"regexp"
	"strconv"
)

// ParseGoVersion parses the specified binary file
// to get the go version used in the build.
func ParseGoVersion(name string) (int, error) {
	ex, err := openExe(name)
	if err != nil {
		return 0, err
	}
	defer ex.Close()

	ver := findVers(ex)
	if len(ver) <= 0 {
		return 0, errors.New("parse buildinfo failed")
	}

	re, err := regexp.Compile(`go(\d+)\.(\d+)\.(\d+).*`)
	if err != nil {
		return 0, err
	}
	match := re.Match([]byte(ver))
	if !match {
		return 0, errors.New("unknown buildinfo")
	}
	sm := re.FindStringSubmatch(ver)
	if len(sm) != 4 {
		return 0, errors.New("unknown buildinfo")
	}

	// Ensure that the minor version has 2 decimal digits
	// For go1.8, the generated number is 108, not 18.
	if len(sm[2]) < 2 {
		sm[2] = "0" + sm[2]
	}
	iv, err := strconv.Atoi(sm[1] + sm[2])
	if err != nil {
		return 0, err
	}
	return iv, nil
}

// The build info blob left by the linker is identified by
// a 16-byte header, consisting of buildInfoMagic (14 bytes),
// the binary's pointer size (1 byte),
// and whether the binary is big endian (1 byte).
var buildInfoMagic = []byte("\xff Go buildinf:")

// findVers finds the go version used to build exe file x.
func findVers(x exeFile) string {
	// Read the first 64kB of text to find the build info blob.
	text := x.DataStart()
	data, err := x.ReadData(text, 64*1024)
	if err != nil {
		return ""
	}
	for ; !bytes.HasPrefix(data, buildInfoMagic); data = data[32:] {
		if len(data) < 32 {
			return ""
		}
	}

	// Decode the blob.
	ptrSize := int(data[14])
	if data[15]&2 != 0 {
		var ver string
		ver, _ = decodeString(data[32:])
		return ver
	} else {
		bigEndian := data[15] != 0
		var bo binary.ByteOrder
		if bigEndian {
			bo = binary.BigEndian
		} else {
			bo = binary.LittleEndian
		}
		var readPtr func([]byte) uint64
		if ptrSize == 4 {
			readPtr = func(b []byte) uint64 { return uint64(bo.Uint32(b)) }
		} else {
			readPtr = bo.Uint64
		}
		return readString(x, ptrSize, readPtr, readPtr(data[16:]))
	}
}

// readString returns the string at address addr in the executable x.
func readString(x exeFile, ptrSize int, readPtr func([]byte) uint64, addr uint64) string {
	hdr, err := x.ReadData(addr, uint64(2*ptrSize))
	if err != nil || len(hdr) < 2*ptrSize {
		return ""
	}
	dataAddr := readPtr(hdr)
	dataLen := readPtr(hdr[ptrSize:])
	data, err := x.ReadData(dataAddr, dataLen)
	if err != nil || uint64(len(data)) < dataLen {
		return ""
	}
	return string(data)
}

func decodeString(data []byte) (s string, rest []byte) {
	u, n := binary.Uvarint(data)
	if n <= 0 || u >= uint64(len(data)-n) {
		return "", nil
	}
	return string(data[n : uint64(n)+u]), data[uint64(n)+u:]
}
