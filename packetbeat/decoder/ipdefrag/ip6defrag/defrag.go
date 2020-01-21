// Copyright 2020 BlueCat Networks (USA) Inc. and its affiliates
// Copyright 2013 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

// Package ip6defrag implements a IPv6 defragmenter

package ip6defrag

import (
	"container/list"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/tsg/gopacket"
	"github.com/tsg/gopacket/layers"
)

//need to check
const (
	IPv6MaximumSize            = 65535
	IPv6MaximumFragmentOffset  = 8191
	IPv6MaximumFragmentListLen = 8191
)

// Quick and Easy to use debug code to trace
// how defrag works.
var debug debugging = false // or flip to true
type debugging bool

func (d debugging) Printf(format string, args ...interface{}) {
	if d {
		log.Printf(format, args...)
	}
}

// NewIPv6Defragmenter returns a new IPv6Defragmenter
// with an initialized map.
func NewIPv6Defragmenter() *IPv6Defragmenter {
	return &IPv6Defragmenter{
		ipFlows: make(map[ipv6]*fragmentList),
	}
}

// DefragIPv6 takes in an IPv6 packet with a fragment payload.
//
func (d *IPv6Defragmenter) DefragIPv6(in *layers.IPv6) (*layers.IPv6, error) {
	return d.DefragIPv6WithTimestamp(in, time.Now())
}

// DefragIPv6WithTimestamp provides functionality of DefragIPv6 with
// an additional timestamp parameter which is used for discarding
// old fragments instead of time.Now()
//
// This is useful when operating on pcap files instead of live captured data
//
func (d *IPv6Defragmenter) DefragIPv6WithTimestamp(in *layers.IPv6, t time.Time) (*layers.IPv6, error) {
	p := gopacket.NewPacket(in.Payload, in.NextLayerType(), gopacket.Default)

	fragL := p.Layer(layers.LayerTypeIPv6Fragment)
	if fragL == nil {
		debug.Printf("defrag: do nothing, do not need anything")
		return in, nil
	}
	frag, _ := fragL.(*layers.IPv6Fragment)

	// perform security check
	if err := d.securityChecks(frag); err != nil {
		debug.Printf("defrag: alert security check")
		return nil, err
	}

	// ok, got a fragment
	debug.Printf("defrag: got in.Id=%d in.FragOffset=%d",
		frag.Identification, frag.FragmentOffset*8)

	// have we already seen a flow between src/st with that Id?
	ipf := newIPv6(in, frag)
	var fl *fragmentList
	var exist bool

	d.Lock()
	fl, exist = d.ipFlows[ipf]
	if !exist {
		debug.Printf("defrag: unknown flow, creating a new one\n")
		fl = new(fragmentList)
		d.ipFlows[ipf] = fl
	}
	d.Unlock()

	// insert, and if final build it
	out, err2 := fl.insert(in, frag, t)

	// at last, if we hit the maximum frag list len
	// without any defrag success, we just drop everything and
	// raise an error
	if out == nil && fl.List.Len()+1 > IPv6MaximumFragmentListLen {
		d.flush(ipf)
		return nil, fmt.Errorf("defrag: Fragment List hits its maximum"+
			"size(%d), without success. Flushing the list",
			IPv6MaximumFragmentListLen)
	}

	// if we got a packet, it's a new one, and he is defragmented
	if out != nil {
		// when defrag is done for a flow between two ip
		// clean the list
		d.flush(ipf)
		return out, nil
	}
	return nil, err2
}

// flush the fragment list for a particular flow
func (d *IPv6Defragmenter) flush(ipf ipv6) {
	d.Lock()
	delete(d.ipFlows, ipf)
	d.Unlock()
}

// newIPv6 returns a new initialized IPv6 Flow
func newIPv6(ip *layers.IPv6, frag *layers.IPv6Fragment) ipv6 {
	return ipv6{
		ip6: ip.NetworkFlow(),
		id:  frag.Identification,
	}
}

func (d *IPv6Defragmenter) securityChecks(in *layers.IPv6Fragment) error {
	if in.FragmentOffset > IPv6MaximumFragmentOffset {
		return fmt.Errorf("defrag: fragment offset too big "+
			"(handcrafted? %d > %d)", in.FragmentOffset, IPv6MaximumFragmentOffset)
	}
	fragOffset := in.FragmentOffset * 8
	if fragOffset+uint16(len(in.Payload)) > IPv6MaximumSize {
		return fmt.Errorf("defrag: fragment will overrun "+
			"(handcrafted? %d > %d)", fragOffset+uint16(len(in.Payload)), IPv6MaximumFragmentOffset)
	}
	return nil
}

// DiscardOlderThan forgets all packets without any activity since
// time t. It returns the number of FragmentList aka number of
// fragment packets it has discarded.
func (d *IPv6Defragmenter) DiscardOlderThan(t time.Time) int {
	var nb int
	d.Lock()
	for k, v := range d.ipFlows {
		if v.LastSeen.Before(t) {
			nb = nb + 1
			delete(d.ipFlows, k)
		}
	}
	d.Unlock()
	return nb
}

// insert insert an IPv6 fragment/packet into the Fragment List
func (f *fragmentList) insert(ip *layers.IPv6, fr *layers.IPv6Fragment, t time.Time) (*layers.IPv6, error) {
	fragOffset := fr.FragmentOffset * 8
	if fragOffset >= f.Highest {
		f.List.PushBack(fr)
	} else {
		for e := f.List.Front(); e != nil; e = e.Next() {
			frag, _ := e.Value.(*layers.IPv6Fragment)
			if fr.FragmentOffset == frag.FragmentOffset {
				// TODO: what if we receive a fragment
				// that begins with duplicate data but
				// *also* has new data? For example:
				//
				// AAAA
				//     BB
				//     BBCC
				//         DDDD
				//
				// In this situation we completely
				// ignore CC and the complete packet can
				// never be reassembled.
				debug.Printf("defrag: ignoring frag %d as we already have it (duplicate?)\n",
					fragOffset)
				return nil, nil
			}

			if fr.FragmentOffset < frag.FragmentOffset {
				debug.Printf("defrag: inserting frag %d before existing frag %d\n",
					fragOffset, frag.FragmentOffset*8)
				f.List.InsertBefore(fr, e)
				break
			}
		}
	}

	f.LastSeen = t

	fragLength := uint16(len(fr.Payload))
	// After inserting the Fragment, we update the counters
	if f.Highest < fragOffset+fragLength {
		f.Highest = fragOffset + fragLength
	}
	f.Current = f.Current + fragLength

	debug.Printf("defrag: insert ListLen: %d Highest:%d Current:%d\n",
		f.List.Len(),
		f.Highest, f.Current)

	// Final Fragment ?
	if !fr.MoreFragments {
		f.FinalReceived = true
	}
	// Ready to try defrag ?
	if f.FinalReceived && f.Highest == f.Current {
		return f.build(ip, fr)
	}
	return nil, nil
}

// Build builds the final datagram, modifying ip in place.
// It puts priority to packet in the early position of the list.
// See Insert for more details.
func (f *fragmentList) build(ip *layers.IPv6, fr *layers.IPv6Fragment) (*layers.IPv6, error) {
	var final []byte
	var currentOffset uint16

	debug.Printf("defrag: building the datagram \n")
	for e := f.List.Front(); e != nil; e = e.Next() {
		frag, _ := e.Value.(*layers.IPv6Fragment)
		if frag.FragmentOffset*8 == currentOffset {
			debug.Printf("defrag: building - adding %d\n", frag.FragmentOffset*8)
			final = append(final, frag.Payload...)
			currentOffset = currentOffset + uint16(len(frag.Payload))
		} else if frag.FragmentOffset*8 < currentOffset {
			// overlapping fragment - let's take only what we need
			startAt := currentOffset - frag.FragmentOffset*8
			debug.Printf("defrag: building - overlapping, starting at %d\n",
				startAt)
			if startAt > uint16(len(frag.Payload)) {
				return nil, errors.New("defrag: building - invalid fragment")
			}
			final = append(final, frag.Payload[startAt:]...)
			currentOffset = currentOffset + frag.FragmentOffset*8
		} else {
			// Houston - we have an hole !
			debug.Printf("defrag: hole found while building, " +
				"stopping the defrag process\n")
			return nil, errors.New("defrag: building - hole found")
		}
		debug.Printf("defrag: building - next is %d\n", currentOffset)
	}

	out := &layers.IPv6{
		Version:      ip.Version,
		TrafficClass: ip.TrafficClass,
		FlowLabel:    ip.FlowLabel,
		Length:       f.Highest,
		NextHeader:   fr.NextHeader,
		HopLimit:     ip.HopLimit,
		SrcIP:        ip.SrcIP,
		DstIP:        ip.DstIP,
		HopByHop:     ip.HopByHop,
	}
	out.Payload = final
	return out, nil
}

// IPv6Defragmenter is a struct which embedded a map of
// all fragment/packet.
type IPv6Defragmenter struct {
	sync.RWMutex
	ipFlows map[ipv6]*fragmentList
}

// ipv6 is a struct to be used as a key.
type ipv6 struct {
	ip6 gopacket.Flow
	id  uint32
}

// fragmentList holds a container/list used to contains IP
// packets/fragments.  It stores internal counters to track the
// maximum total of byte, and the current length it has received.
// It also stores a flag to know if he has seen the last packet.
type fragmentList struct {
	List          list.List
	Highest       uint16
	Current       uint16
	FinalReceived bool
	LastSeen      time.Time
}
