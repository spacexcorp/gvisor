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

package tcp

import (
	"gvisor.dev/gvisor/pkg/sync"
)

// segmentQueue is a bounded, thread-safe queue of TCP segments.
//
// +stateify savable
type segmentQueue struct {
	mu     sync.Mutex  `state:"nosave"`
	list   segmentList `state:"wait"`
	ep     *endpoint
	frozen bool
}

// emptyLocked determines if the queue is empty.
// Preconditions: q.mu must be held.
func (q *segmentQueue) emptyLocked() bool {
	return q.list.Empty()
}

// empty determines if the queue is empty.
func (q *segmentQueue) empty() bool {
	q.mu.Lock()
	r := q.emptyLocked()
	q.mu.Unlock()

	return r
}

// enqueue adds the given segment to the queue.
//
// Returns true when the segment is successfully added to the queue, in which
// case ownership of the reference is transferred to the queue. And returns
// false if the queue is full, in which case ownership is retained by the
// caller.
func (q *segmentQueue) enqueue(s *segment) bool {
	// q.ep.receiveBufferParams() must be called without holding q.mu to
	// avoid lock order inversion.
	bufSz := q.ep.receiveBufferSize()
	used := q.ep.receiveMemUsed()
	q.mu.Lock()
	// We allow at least 1 extra segment to be queued.
	allow := used <= bufSz
	if allow && !q.frozen {
		q.list.PushBack(s)
		// Set the owner now that the endpoint owns the segment.
		s.setOwner(q.ep, recvQ)
	}
	q.mu.Unlock()

	return allow
}

// dequeue removes and returns the next segment from queue, if one exists.
// Ownership is transferred to the caller, who is responsible for decrementing
// the ref count when done.
func (q *segmentQueue) dequeue() *segment {
	q.mu.Lock()
	s := q.list.Front()
	if s != nil {
		q.list.Remove(s)
	}
	q.mu.Unlock()

	return s
}

// freeze when called will disallow any more segments from being queued till
// thaw is called.
func (q *segmentQueue) freeze() {
	q.mu.Lock()
	q.frozen = true
	q.mu.Unlock()
}

// thaw unfreezes a previously frozen queue and allows new segments to be queued
// again.
func (q *segmentQueue) thaw() {
	q.mu.Lock()
	q.frozen = false
	q.mu.Unlock()
}
