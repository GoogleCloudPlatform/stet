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

// Package transportshim implements the net.Conn interface. Used for to enable
// the `crypto/tls` package to implement TLS over any transport layer.
package transportshim

import (
	"net"
	"time"
)

// In the event that more data is written to sendBuf than the underlying
// TLS implementation can read at once, the sendBuf channel will need to
// buffer multiple byte slices. In initial testing, the TLS implementation
// can read somewhere between 2KB to 8KB per call, and the largest vTPM
// attestation is on the order of 32KB, so we set the size of the channel
// to 100 to accomodate for this.
const sendBufLen = 100

// Allow 1 MB of bytes to be buffered through the receiveBuf channel.
const receiveBufLen = 1024 * 1024

// TransportShim handles shuttling data.
// When used on the server side, receiveBuf holds records sent from the client
// and sendBuf is for records generated by the server to be sent to the client.
// When used on the client side, receiveBuf holds records sent from the server
// and sendBuf is for records generated by the client to be sent to the server.
type TransportShim struct {
	sendBuf    chan []byte
	receiveBuf chan byte
}

// NewTransportShim initializes and returns the transport shim.
func NewTransportShim() ShimInterface {
	t := &TransportShim{}
	t.sendBuf = make(chan []byte, sendBufLen)
	t.receiveBuf = make(chan byte, receiveBufLen)
	return t
}

// QueueReceiveBuf inputs data receved from the counterparty, to be read.
func (shim *TransportShim) QueueReceiveBuf(buf []byte) {
	for _, b := range buf {
		shim.receiveBuf <- b
	}
}

func (shim *TransportShim) Read(b []byte) (n int, err error) {
	if len(b) == 0 {
		return 0, nil
	}

	// Block until we can read at least one byte, as per https://pkg.go.dev/io#Reader.
	b[0] = <-shim.receiveBuf

	// Read as many remaining bytes from `receiveBuf` as available, stopping if
	// we have read len(b) bytes, noting that we are starting at the 2nd byte.
	for i := range b[1:] {
		select {
		case b[i+1] = <-shim.receiveBuf:
		default:
			// Nothing left to read from channel.
			return i + 1, nil
		}
	}
	return len(b), nil
}

// DrainSendBuf returns records from `sendBuf` to be sent to the counterparty
// (over some transport, i.e., gRPC). Will block until Write is invoked with
// data to be sent to the counterparty.
func (shim *TransportShim) DrainSendBuf() []byte {
	// Block until at least one slice of bytes is available in the sendBuf channel.
	ret := <-shim.sendBuf

	// Then, exhaust the remainder of the channel.
	for {
		select {
		case b := <-shim.sendBuf:
			ret = append(ret, b...)
		default:
			return ret
		}
	}
}

func (shim *TransportShim) Write(b []byte) (n int, err error) {
	buf := make([]byte, len(b))
	copy(buf, b)
	shim.sendBuf <- buf
	return len(buf), nil
}

// Close not implemented
func (shim *TransportShim) Close() error {
	panic("Close not implemented")
}

// LocalAddr not implemented
func (shim *TransportShim) LocalAddr() net.Addr {
	panic("LocalAddr not implemented")
}

// RemoteAddr not implemented
func (shim *TransportShim) RemoteAddr() net.Addr {
	panic("RemoteAddr not implemented")
}

// SetDeadline not implemented
func (shim *TransportShim) SetDeadline(t time.Time) error {
	panic("SetDeadline not implemented")
}

// SetReadDeadline not implemented
func (shim *TransportShim) SetReadDeadline(t time.Time) error {
	panic("SetReadDeadline not implemented")
}

// SetWriteDeadline not implemented
func (shim *TransportShim) SetWriteDeadline(t time.Time) error {
	panic("SetWriteDeadline not implemented")
}
