// Copyright 2017 EXARING AG. All Rights Reserved.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//     http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package sfserver provides sflow collection services via UDP and passes flows into annotator layer
package sfserver

import (
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/bio-routing/tflow2/config"
	"github.com/bio-routing/tflow2/convert"
	"github.com/bio-routing/tflow2/netflow"
	"github.com/bio-routing/tflow2/packet"
	"github.com/bio-routing/tflow2/sflow"
	"github.com/bio-routing/tflow2/srcache"
	"github.com/bio-routing/tflow2/stats"
	"github.com/pkg/errors"

	log "github.com/sirupsen/logrus"
)

// SflowServer represents a sflow Collector instance
type SflowServer struct {
	// Output is the channel used to send flows to the annotator layer
	Output chan *netflow.Flow

	// debug defines the debug level
	debug int

	// bgpAugment is used to decide if ASN information from netflow packets should be used
	bgpAugment bool

	// con is the UDP socket
	conn *net.UDPConn

	wg sync.WaitGroup

	config *config.Config

	sampleRateCache *srcache.SamplerateCache
}

// New creates and starts a new `SflowServer` instance
func New(numReaders int, config *config.Config, sampleRateCache *srcache.SamplerateCache) *SflowServer {
	sfs := &SflowServer{
		Output:          make(chan *netflow.Flow),
		config:          config,
		sampleRateCache: sampleRateCache,
	}

	addr, err := net.ResolveUDPAddr("udp", sfs.config.Sflow.Listen)
	if err != nil {
		panic(fmt.Sprintf("ResolveUDPAddr: %v", err))
	}

	con, err := net.ListenUDP("udp", addr)
	if err != nil {
		panic(fmt.Sprintf("Listen: %v", err))
	}

	// Create goroutines that read netflow packet and process it
	for i := 0; i < numReaders; i++ {
		sfs.wg.Add(numReaders)
		go func(num int) {
			sfs.packetWorker(num, con)
		}(i)
	}

	return sfs
}

// Close closes the socket and stops the workers
func (sfs *SflowServer) Close() {
	sfs.conn.Close()
	sfs.wg.Wait()
}

// packetWorker reads netflow packet from socket and handsoff processing to processFlowSets()
func (sfs *SflowServer) packetWorker(identity int, conn *net.UDPConn) {
	buffer := make([]byte, 8960)
	for {
		length, remote, err := conn.ReadFromUDP(buffer)
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Errorf("Error reading from socket: %v", err)
			continue
		}
		atomic.AddUint64(&stats.GlobalStats.SflowPackets, 1)
		atomic.AddUint64(&stats.GlobalStats.SflowBytes, uint64(length))

		remote.IP = remote.IP.To4()
		if remote.IP == nil {
			log.Errorf("Received IPv6 packet. Dropped.")
			continue
		}

		sfs.processPacket(remote.IP, buffer[:length])
	}
	sfs.wg.Done()
}

// processPacket takes a raw sflow packet, send it to the decoder and passes the decoded packet
func (sfs *SflowServer) processPacket(agent net.IP, buffer []byte) {
	length := len(buffer)
	p, err := sflow.Decode(buffer[:length], agent)
	if err != nil {
		log.Errorf("sflow.Decode: %v", err)
		return
	}

	for _, fs := range p.FlowSamples {
		if fs.RawPacketHeader == nil {
			log.Infof("Received sflow packet without raw packet header. Skipped.")
			continue
		}

		if fs.Data == nil {
			log.Infof("Received sflow packet without raw packet header. Skipped.")
			continue
		}

		if fs.RawPacketHeader.HeaderProtocol != 1 {
			log.Infof("Unknown header protocol: %d", fs.RawPacketHeader.HeaderProtocol)
			continue
		}

		ether, err := packet.DecodeEthernet(fs.Data, fs.RawPacketHeader.OriginalPacketLength)
		if err != nil {
			log.Infof("Unable to decode ether packet: %v", err)
			continue
		}
		fs.Data = unsafe.Pointer(uintptr(fs.Data) - packet.SizeOfEthernetII)
		fs.DataLen -= uint32(packet.SizeOfEthernetII)

		fl := &netflow.Flow{
			Router:     agent,
			IntIn:      fs.FlowSampleHeader.InputIf,
			IntOut:     fs.FlowSampleHeader.OutputIf,
			Size:       uint64(fs.RawPacketHeader.FlowDataLength),
			Packets:    uint32(1),
			Timestamp:  time.Now().Unix(),
			Samplerate: uint64(fs.FlowSampleHeader.SamplingRate),
		}

		// We're updating the sampleCache to allow the forntend to show current sampling rates
		sfs.sampleRateCache.Set(agent, uint64(fs.FlowSampleHeader.SamplingRate))

		if fs.ExtendedRouterData == nil {
			continue
		}
		fl.NextHop = fs.ExtendedRouterData.NextHop

		sfs.processEthernet(ether.EtherType, fs, fl)
		sfs.Output <- fl
	}
}

func (sfs *SflowServer) processEthernet(ethType uint16, fs *sflow.FlowSample, fl *netflow.Flow) {
	if ethType == packet.EtherTypeIPv4 {
		sfs.processIPv4Packet(fs, fl)
	} else if ethType == packet.EtherTypeIPv6 {
		sfs.processIPv6Packet(fs, fl)
	} else if ethType == packet.EtherTypeARP || ethType == packet.EtherTypeLACP {
		return
	} else if ethType == packet.EtherTypeIEEE8021Q {
		sfs.processDot1QPacket(fs, fl)
	} else {
		log.Errorf("Unknown EtherType: 0x%x", ethType)
	}
}

func (sfs *SflowServer) processDot1QPacket(fs *sflow.FlowSample, fl *netflow.Flow) {
	dot1q, err := packet.DecodeDot1Q(fs.Data, fs.DataLen)
	if err != nil {
		log.Errorf("Unable to decode dot1q header: %v", err)
	}
	fs.Data = unsafe.Pointer(uintptr(fs.Data) - packet.SizeOfDot1Q)
	fs.DataLen -= uint32(packet.SizeOfDot1Q)

	sfs.processEthernet(dot1q.EtherType, fs, fl)
}

func (sfs *SflowServer) processIPv4Packet(fs *sflow.FlowSample, fl *netflow.Flow) {
	fl.Family = 4
	ipv4, err := packet.DecodeIPv4(fs.Data, fs.DataLen)
	if err != nil {
		log.Errorf("Unable to decode IPv4 packet: %v", err)
	}
	fs.Data = unsafe.Pointer(uintptr(fs.Data) - packet.SizeOfIPv4Header)
	fs.DataLen -= uint32(packet.SizeOfIPv4Header)

	fl.SrcAddr = convert.Reverse(ipv4.SrcAddr[:])
	fl.DstAddr = convert.Reverse(ipv4.DstAddr[:])
	fl.Protocol = uint32(ipv4.Protocol)
	switch ipv4.Protocol {
	case packet.TCP:
		if err := getTCP(fs.Data, fs.DataLen, fl); err != nil {
			log.Errorf("%v", err)
		}
	case packet.UDP:
		if err := getUDP(fs.Data, fs.DataLen, fl); err != nil {
			log.Errorf("%v", err)
		}
	}
}

func (sfs *SflowServer) processIPv6Packet(fs *sflow.FlowSample, fl *netflow.Flow) {
	fl.Family = 6
	ipv6, err := packet.DecodeIPv6(fs.Data, fs.DataLen)
	if err != nil {
		log.Errorf("Unable to decode IPv6 packet: %v", err)
	}
	fs.Data = unsafe.Pointer(uintptr(fs.Data) - packet.SizeOfIPv6Header)
	fs.DataLen -= uint32(packet.SizeOfIPv6Header)

	fl.SrcAddr = convert.Reverse(ipv6.SrcAddr[:])
	fl.DstAddr = convert.Reverse(ipv6.DstAddr[:])
	fl.Protocol = uint32(ipv6.NextHeader)
	switch ipv6.NextHeader {
	case packet.TCP:
		if err := getTCP(fs.Data, fs.DataLen, fl); err != nil {
			log.Errorf("%v", err)
		}
	case packet.UDP:
		if err := getUDP(fs.Data, fs.DataLen, fl); err != nil {
			log.Errorf("%v", err)
		}
	}
}

func getUDP(udpPtr unsafe.Pointer, length uint32, fl *netflow.Flow) error {
	udp, err := packet.DecodeUDP(udpPtr, length)
	if err != nil {
		return errors.Wrap(err, "Unable to decode UDP datagram")
	}

	fl.SrcPort = uint32(udp.SrcPort)
	fl.DstPort = uint32(udp.DstPort)

	return nil
}

func getTCP(tcpPtr unsafe.Pointer, length uint32, fl *netflow.Flow) error {
	tcp, err := packet.DecodeTCP(tcpPtr, length)
	if err != nil {
		return errors.Wrap(err, "Unable to decode TCP segment")
	}

	fl.SrcPort = uint32(tcp.SrcPort)
	fl.DstPort = uint32(tcp.DstPort)

	return nil
}

// Dump dumps a flow on the screen
func Dump(fl *netflow.Flow) {
	fmt.Printf("--------------------------------\n")
	fmt.Printf("Flow dump:\n")
	fmt.Printf("Router: %d\n", fl.Router)
	fmt.Printf("Family: %d\n", fl.Family)
	fmt.Printf("SrcAddr: %s\n", net.IP(fl.SrcAddr).String())
	fmt.Printf("DstAddr: %s\n", net.IP(fl.DstAddr).String())
	fmt.Printf("Protocol: %d\n", fl.Protocol)
	fmt.Printf("NextHop: %s\n", net.IP(fl.NextHop).String())
	fmt.Printf("IntIn: %d\n", fl.IntIn)
	fmt.Printf("IntOut: %d\n", fl.IntOut)
	fmt.Printf("Packets: %d\n", fl.Packets)
	fmt.Printf("Bytes: %d\n", fl.Size)
	fmt.Printf("--------------------------------\n")
}
