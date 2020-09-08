// Copyright 2018 The gVisor Authors.
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

// Package fragmentation contains the implementation of IP fragmentation.
// It is based on RFC 791, RFC 815 and RFC 8200.
package fragmentation

import (
	"errors"
	"fmt"
	"log"
	"time"

	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

const (
	// DefaultReassembleTimeout is based on the linux stack: net.ipv4.ipfrag_time.
	DefaultReassembleTimeout = 30 * time.Second

	// HighFragThreshold is the threshold at which we start trimming old
	// fragmented packets. Linux uses a default value of 4 MB. See
	// net.ipv4.ipfrag_high_thresh for more information.
	HighFragThreshold = 4 << 20 // 4MB

	// LowFragThreshold is the threshold we reach to when we start dropping
	// older fragmented packets. It's important that we keep enough room for newer
	// packets to be re-assembled. Hence, this needs to be lower than
	// HighFragThreshold enough. Linux uses a default value of 3 MB. See
	// net.ipv4.ipfrag_low_thresh for more information.
	LowFragThreshold = 3 << 20 // 3MB

	// minBlockSize is the minimum block size for fragments.
	minBlockSize = 1
)

var (
	// ErrInvalidArgs indicates to the caller that that an invalid argument was
	// provided.
	ErrInvalidArgs = errors.New("invalid args")
)

// FragmentID is the identifier for a fragment.
type FragmentID struct {
	// Source is the source address of the fragment.
	Source tcpip.Address

	// Destination is the destination address of the fragment.
	Destination tcpip.Address

	// ID is the identification value of the fragment.
	//
	// This is a uint32 because IPv6 uses a 32-bit identification value.
	ID uint32

	// The protocol for the packet.
	Protocol uint8
}

// Fragmentation is the main structure that other modules
// of the stack should use to implement IP Fragmentation.
type Fragmentation struct {
	mu           sync.Mutex
	highLimit    int
	lowLimit     int
	reassemblers map[FragmentID]*reassembler
	rList        reassemblerList
	size         int
	timeout      time.Duration
	blockSize    uint16
}

// NewFragmentation creates a new Fragmentation.
//
// blockSize specifies the fragment block size, in bytes.
//
// highMemoryLimit specifies the limit on the memory consumed
// by the fragments stored by Fragmentation (overhead of internal data-structures
// is not accounted). Fragments are dropped when the limit is reached.
//
// lowMemoryLimit specifies the limit on which we will reach by dropping
// fragments after reaching highMemoryLimit.
//
// reassemblingTimeout specifies the maximum time allowed to reassemble a packet.
// Fragments are lazily evicted only when a new a packet with an
// already existing fragmentation-id arrives after the timeout.
func NewFragmentation(blockSize uint16, highMemoryLimit, lowMemoryLimit int, reassemblingTimeout time.Duration) *Fragmentation {
	if lowMemoryLimit >= highMemoryLimit {
		lowMemoryLimit = highMemoryLimit
	}

	if lowMemoryLimit < 0 {
		lowMemoryLimit = 0
	}

	if blockSize < minBlockSize {
		blockSize = minBlockSize
	}

	return &Fragmentation{
		reassemblers: make(map[FragmentID]*reassembler),
		highLimit:    highMemoryLimit,
		lowLimit:     lowMemoryLimit,
		timeout:      reassemblingTimeout,
		blockSize:    blockSize,
	}
}

// Process processes an incoming fragment belonging to an ID and returns a
// complete packet and its protocol number when all the packets belonging to
// that ID have been received.
//
// [first, last] is the range of the fragment bytes.
//
// first must be a multiple of the block size f is configured with. The size
// of the fragment data must be a multiple of the block size, unless there are
// no fragments following this fragment (more set to false).
//
// proto is the protocol number marked in the fragment being processed. It has
// to be given here outside of the FragmentID struct because IPv6 should not use
// the protocol to identify a fragment.
func (f *Fragmentation) Process(
	id FragmentID, first, last uint16, more bool, proto uint8, vv buffer.VectorisedView) (
	buffer.VectorisedView, uint8, bool, error) {
	if first > last {
		return buffer.VectorisedView{}, 0, false, fmt.Errorf("first=%d is greater than last=%d: %w", first, last, ErrInvalidArgs)
	}

	if first%f.blockSize != 0 {
		return buffer.VectorisedView{}, 0, false, fmt.Errorf("first=%d is not a multiple of block size=%d: %w", first, f.blockSize, ErrInvalidArgs)
	}

	fragmentSize := last - first + 1
	if more && fragmentSize%f.blockSize != 0 {
		return buffer.VectorisedView{}, 0, false, fmt.Errorf("fragment size=%d bytes is not a multiple of block size=%d on non-final fragment: %w", fragmentSize, f.blockSize, ErrInvalidArgs)
	}

	if l := vv.Size(); l < int(fragmentSize) {
		return buffer.VectorisedView{}, 0, false, fmt.Errorf("got fragment size=%d bytes less than the expected fragment size=%d bytes (first=%d last=%d): %w", l, fragmentSize, first, last, ErrInvalidArgs)
	}
	vv.CapLength(int(fragmentSize))

	f.mu.Lock()
	r, ok := f.reassemblers[id]
	if ok && r.tooOld(f.timeout) {
		// This is very likely to be an id-collision or someone performing a slow-rate attack.
		f.release(r)
		ok = false
	}
	if !ok {
		r = newReassembler(id)
		f.reassemblers[id] = r
		f.rList.PushFront(r)
	}
	f.mu.Unlock()

	res, firstFragmentProto, done, consumed, err := r.process(first, last, more, proto, vv)
	if err != nil {
		// We probably got an invalid sequence of fragments. Just
		// discard the reassembler and move on.
		f.mu.Lock()
		f.release(r)
		f.mu.Unlock()
		return buffer.VectorisedView{}, 0, false, fmt.Errorf("fragmentation processing error: %w", err)
	}
	f.mu.Lock()
	f.size += consumed
	if done {
		f.release(r)
	}
	// Evict reassemblers if we are consuming more memory than highLimit until
	// we reach lowLimit.
	if f.size > f.highLimit {
		for f.size > f.lowLimit {
			tail := f.rList.Back()
			if tail == nil {
				break
			}
			f.release(tail)
		}
	}
	f.mu.Unlock()
	return res, firstFragmentProto, done, nil
}

func (f *Fragmentation) release(r *reassembler) {
	// Before releasing a fragment we need to check if r is already marked as done.
	// Otherwise, we would delete it twice.
	if r.checkDoneOrMark() {
		return
	}

	delete(f.reassemblers, r.id)
	f.rList.Remove(r)
	f.size -= r.size
	if f.size < 0 {
		log.Printf("memory counter < 0 (%d), this is an accounting bug that requires investigation", f.size)
		f.size = 0
	}
}

// PacketFragmenter is the book-keeping struct for packet fragmentation.
type PacketFragmenter struct {
	transportHeader          buffer.View
	data                     buffer.VectorisedView
	baseReserve              int
	innerMTU                 int
	fragmentCount            uint32
	currentFragment          uint32
	fragmentOffset           uint16
	transportHeaderFitsFirst bool
}

// MakePacketFragmenter prepares the struct needed for packet fragmentation.
//
// pkt is the packet to be fragmented.
//
// mtu is the maximum size of the payload a Link layer frame can take. Each
// generated fragment must fit in it (Network headers included).
//
// extraHeaderLength can be used to reserve extra space for the headers, if we
// need more than what is pre-allocated in the initial packet.
func MakePacketFragmenter(pkt *stack.PacketBuffer, mtu uint32, extraHeaderLength int) PacketFragmenter {
	// Each fragment will *at least* reserve the bytes available to the Link Layer
	// (which are currently the only unused header bytes) and the bytes dedicated
	// to the Network header.
	baseReserve := pkt.AvailableHeaderBytes() + pkt.NetworkHeader().View().Size() + extraHeaderLength
	innerMTU := int(mtu) - pkt.NetworkHeader().View().Size() - extraHeaderLength

	// Round the MTU down to align to 8 bytes.
	innerMTU &^= 7

	// As per RFC 8200 Section 4.5, some IPv6 extension headers should not be
	// repeated in each fragment. However we do not currently support any header
	// of that kind yet, so the following computation is valid for both IPv4 and
	// IPv6.
	// TODO(gvisor.dev/issue/3912): Once Authentication and/or ESP Headers are
	// supported for outbound packets, the length of the IPv6 fragmentable part
	// need to take these headers into account.
	fragmentablePartLength := pkt.TransportHeader().View().Size() + pkt.Data.Size()

	return PacketFragmenter{
		transportHeader:          pkt.TransportHeader().View(),
		data:                     pkt.Data,
		baseReserve:              baseReserve,
		innerMTU:                 innerMTU,
		fragmentCount:            uint32((fragmentablePartLength + innerMTU - 1) / innerMTU),
		transportHeaderFitsFirst: pkt.TransportHeader().View().Size() <= innerMTU,
	}
}

// BuildNextFragment returns a packet with the payload of the next fragment,
// along with the fragment's offset, the number of bytes copied and a boolean
// indicating if there are more fragments left or not. If this function is
// called again after it indicated that no more fragments were left, it will
// panic.
//
// Note that the returned packet will not have its network header & link headers
// populated, but the space for them will be reserved. The first fragment may
// have its transport header populated.
func (pf *PacketFragmenter) BuildNextFragment(proto tcpip.NetworkProtocolNumber) (*stack.PacketBuffer, uint16, uint16, bool) {
	if pf.currentFragment >= pf.fragmentCount {
		panic("BuildNextFragment should not be called again after every fragment was built")
	}

	reserve := pf.baseReserve

	// Where possible, the first fragment that is sent has the same
	// number of bytes reserved for header as the input packet. The link-layer
	// endpoint may depend on this for looking at, eg, L4 headers.
	if pf.currentFragment == 0 && pf.transportHeaderFitsFirst {
		reserve += pf.transportHeader.Size()
	}

	fragPkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: reserve,
	})
	fragPkt.NetworkProtocolNumber = proto

	// Copy data for the fragment.
	avail := pf.innerMTU

	if n := len(pf.transportHeader); n > 0 {
		if n > avail {
			n = avail
		}
		if pf.currentFragment == 0 && pf.transportHeaderFitsFirst {
			if copied := copy(fragPkt.TransportHeader().Push(n), pf.transportHeader); copied < n {
				panic(fmt.Sprintf("wrong number of bytes copied into transport header: got %d, want %d", copied, n))
			}
		} else {
			fragPkt.Data.AppendView(pf.transportHeader[:n:n])
		}
		pf.transportHeader = pf.transportHeader[n:]
		avail -= n
	}

	if avail > 0 {
		n := pf.data.Size()
		if n > avail {
			n = avail
		}
		pf.data.ReadToVV(&fragPkt.Data, n)
		avail -= n
	}

	offset := pf.fragmentOffset
	copied := uint16(pf.innerMTU - avail)

	pf.fragmentOffset += copied
	pf.currentFragment++

	more := pf.currentFragment != pf.fragmentCount

	return fragPkt, offset, copied, more
}
