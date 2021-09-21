// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package client

import (
	"bytes"
	"io"
	"testing"
)

func TestReadWriteHeaderSucceeds(t *testing.T) {
	var file bytes.Buffer

	if err := writeHeader(&file, 42); err != nil {
		t.Fatalf("writeHeader(file, 42) returned error: %v", err)
	}

	header, err := readHeader(&file)
	if err != nil {
		t.Fatalf("readHeader(file) returned error: %v", err)
	}

	if !bytes.Equal(header.Magic[:], STETMagic[:]) {
		t.Fatalf("Header does not contain expected magic string: got %v, want %v", header.Magic, STETMagic)
	}

	if header.MetadataLen != 42 {
		t.Fatalf("Header had unexpected MetadataLen: got %v, want 42", header.MetadataLen)
	}
}

func TestWriteHeaderExplicitByteOrder(t *testing.T) {
	var header bytes.Buffer

	if err := writeHeader(&header, 0xABCD); err != nil {
		t.Fatalf("writeHeader(header, 0xABCD) returned error: %v", err)
	}

	var want []byte
	want = append(want, STETMagic[:]...)
	want = append(want, 0x01)                  // version number
	want = append(want, []byte{0xCD, 0xAB}...) // metadata length (little-endian)

	if !bytes.Equal(header.Bytes(), want) {
		t.Fatalf("writeHeader(header, 0xABCD) produced unexpected header: got %v, want %v", header.Bytes(), want)
	}
}

func TestReadHeaderAdvances16Bytes(t *testing.T) {
	var file bytes.Buffer

	if err := writeHeader(&file, 42); err != nil {
		t.Fatalf("writeHeader(file, 42) returned error: %v", err)
	}

	// Write more to the buffer so the reader can potentially read further.
	file.Write([]byte("I am a file hungry for more and more data."))

	reader := bytes.NewReader(file.Bytes())

	if _, err := readHeader(reader); err != nil {
		t.Fatalf("readHeader(file) returned error: %v", err)
	}

	pos, err := reader.Seek(0, io.SeekCurrent)
	if err != nil {
		t.Fatalf("reader.Seek(0, io.SeekCurrent) returned error: %v", err)
	}

	if pos != 16 {
		t.Fatalf("readHeader(file) got %d bytes, want 16 bytes", pos)
	}
}

func TestReadWriteHeaderFailsBadHeader(t *testing.T) {
	var file bytes.Buffer

	if err := writeHeader(&file, 42); err != nil {
		t.Fatalf("writeHeader(file, 42) returned error: %v", err)
	}

	// Seek forward one byte, which should mess up the header read.
	file.ReadByte()

	if _, err := readHeader(&file); err == nil {
		t.Fatalf("readHeader(file) = %v, want invalid header error", err)
	}
}

func TestReadWriteHeaderFailsBadMagicString(t *testing.T) {
	var file bytes.Buffer

	if err := writeHeader(&file, 42); err != nil {
		t.Fatalf("writeHeader(file, 42) returned error: %v", err)
	}

	// Replace the first byte of the magic string with a null byte.
	header := file.Bytes()
	header[0] = 0x00
	headerBuf := bytes.NewBuffer(header)

	if _, err := readHeader(headerBuf); err == nil {
		t.Fatalf("readHeader(file) = %v, want bad magic string error", err)
	}
}
