package tcp

import (
	"fmt"
	"log"
	"net"
	"scan_server/pkg"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type SYNScanOpt struct {
	srcIp   net.IP
	srcMac  net.HardwareAddr
	dstIp   net.IP
	dstPort layers.TCPPort
}

func NewSYNScanOpt(target net.IP, port uint16) (*SYNScanOpt, error) {
	//fmt.Println(pcap.Version())

	iFace, ip, er := pkg.GetIFace(&net.IPNet{IP: target, Mask: net.CIDRMask(32, 32)})
	if er != nil {
		return nil, er
	}
	return &SYNScanOpt{
		srcIp:   ip.To4(),
		srcMac:  iFace.HardwareAddr,
		dstIp:   target.To4(),
		dstPort: layers.TCPPort(port),
	}, nil
}

func (s *SYNScanOpt) SYNScan() {
	gwMac := pkg.GetMac(s.srcIp, s.dstIp, s.srcMac)
	//fmt.Println("gwMac:", gwMac)

	eth := layers.Ethernet{
		SrcMAC:       s.srcMac,
		DstMAC:       gwMac,
		EthernetType: layers.EthernetTypeIPv4,
	}

	ipv4 := layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    s.srcIp,
		DstIP:    s.dstIp,
	}
	tcp := layers.TCP{
		SrcPort: 22223,
		DstPort: s.dstPort,
		SYN:     true,
	}

	fmt.Println("srcIp:", s.srcIp)
	fmt.Println("srcMac:", s.srcMac)
	fmt.Println("dstIp:", s.dstIp)
	fmt.Println("gwMac:", gwMac)
	fmt.Println("dstPort:", s.dstPort)
	tcp.SetNetworkLayerForChecksum(&ipv4)

	ipFlow := gopacket.NewFlow(layers.EndpointIPv4, s.dstIp, s.srcIp)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	if err := gopacket.SerializeLayers(buf, opts, &eth, &ipv4, &tcp); err != nil {
		panic(err)
	}

	ifs, err := pcap.FindAllDevs()
	if err != nil {
		log.Panic(err)
	}
	var device string
Loop:
	for _, dev := range ifs {
		for _, address := range dev.Addresses {
			if address.IP.String() == s.srcIp.String() {
				device = dev.Name
				break Loop
			}
		}
	}
	handle, err := pcap.OpenLive(device, 65536, true, pcap.BlockForever)
	if err != nil {
		log.Panic(err)
	}
	handle.WritePacketData(buf.Bytes())
	time.Sleep(time.Second * 5)
	//start := time.Now()
	for {
		// Time out 5 seconds after the last packet we sent.
		//if time.Since(start) > time.Second*10 {
		//	log.Printf("timed out for %v:%d, assuming we've seen all we can", s.dstIp, s.dstPort)
		//	return
		//}
		// Read in the next packet.
		data, _, err := handle.ReadPacketData()
		if err == pcap.NextErrorTimeoutExpired {
			return
		} else if err != nil {
			log.Printf("error reading packet: %v", err)
			return
		}

		// Parse the packet.  We'd use DecodingLayerParser here if we
		// wanted to be really fast.
		packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.NoCopy)

		// Find the packets we care about, and print out logging
		// information about them.  All others are ignored.
		if net := packet.NetworkLayer(); net == nil {
			// log.Printf("packet has no network layer")
		} else if net.NetworkFlow() != ipFlow {
			// log.Printf("packet does not match our ip src/dst")
		} else if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer == nil {
			// log.Printf("packet has not tcp layer")
		} else if tcp, ok := tcpLayer.(*layers.TCP); !ok {
			// We panic here because this is guaranteed to never
			// happen.
			panic("tcp layer is not tcp layer :-/")
		} else if tcp.DstPort != 22223 {
			// log.Printf("dst port %v does not match", tcp.DstPort)
		} else if tcp.RST {
			log.Printf("  port %v closed", tcp.SrcPort)
			return
		} else if tcp.SYN && tcp.ACK {
			log.Printf("  port %v open", tcp.SrcPort)
			return
		} else {
			// log.Printf("ignoring useless packet")
		}
	}
}
