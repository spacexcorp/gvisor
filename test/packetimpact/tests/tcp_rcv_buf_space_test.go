// Copyright 2020 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tcp_rcv_buf_space_test

import (
	"context"
	"flag"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/test/packetimpact/testbench"
)

func init() {
	testbench.RegisterFlags(flag.CommandLine)
}

// TestReduceRecvBuf tests that a packet within window is still dropped
// if the available buffer space drops below the size of the incoming
// segment.
func TestReduceRecvBuf(t *testing.T) {
	dut := testbench.NewDUT(t)
	defer dut.TearDown()
	listenFd, remotePort := dut.CreateListener(t, unix.SOCK_STREAM, unix.IPPROTO_TCP, 1)
	defer dut.Close(t, listenFd)
	conn := testbench.NewTCPIPv4(t, testbench.TCP{DstPort: &remotePort}, testbench.TCP{SrcPort: &remotePort})
	defer conn.Close(t)

	conn.Connect(t)
	acceptFd, _ := dut.Accept(t, listenFd)
	defer dut.Close(t, acceptFd)

	const rcvBufSz = 4096 // 4KiB
	dut.SetSockOptInt(t, acceptFd, unix.SOL_SOCKET, unix.SO_RCVBUF, rcvBufSz)

	// 8KiB + 1 will result the last segment being dropped in case of linux but in
	// case of gvisor we will probably drop the 3rd segment itself ( assuming an
	// MTU of 1500 bytes).
	sampleData := testbench.GenerateRandomPayload(t, rcvBufSz*2+1)
	// Send and receive sample data to the dut.
	pktSize := 1400
	sent := 0
	for len(sampleData)-sent > 0 {
		payloadSz := pktSize
		if sent+pktSize > len(sampleData) {
			payloadSz = len(sampleData) - sent
		}
		payload := sampleData[sent : sent+payloadSz]
		conn.Send(t, testbench.TCP{Flags: testbench.Uint8(header.TCPFlagAck)}, []testbench.Layer{&testbench.Payload{Bytes: payload}}...)
		sent += payloadSz
	}
	// First read should read < len(sampleData)
	if ret, _, err := dut.RecvWithErrno(context.Background(), t, acceptFd, int32(len(sampleData)), 0); ret == -1 || int(ret) == len(sampleData) {
		t.Fatalf("dut.RecvWithErrno(ctx, t, %d, %d, 0) = %d,_, %s", acceptFd, int32(len(sampleData)), ret, err)
	}
	// Second read should return EAGAIN as the last segment should have been
	// dropped due it exceeding the receive buffer space available in the socket.
	if ret, got, err := dut.RecvWithErrno(context.Background(), t, acceptFd, int32(len(sampleData)), syscall.MSG_DONTWAIT); got != nil || ret != -1 || err != syscall.EAGAIN {
		t.Fatalf("expected no packets but got: %s", got)
	}
}
