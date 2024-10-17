package pkg

import (
	"errors"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/libp2p/go-netroute"
)

var (
	ErrInvalidAddr = errors.New("invalid addr not subnet/host")
	ErrInvalidPort = errors.New("invalid port range")
)

func GetSendIp() (net.IP, error) {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP, nil
}

func GetIFace(dstSubnet *net.IPNet) (*net.Interface, *net.IP, error) {
	dstSubnetIp := dstSubnet.IP.Mask(dstSubnet.Mask)
	iFaces, err := net.Interfaces()
	if err != nil {
		return nil, nil, err
	}
	for _, iFaceTmp := range iFaces {
		iFaceAdds, err := iFaceTmp.Addrs()
		if err != nil {
			log.Println(err)
			continue
		}
		for _, addr := range iFaceAdds {
			if ipNet, ok := addr.(*net.IPNet); ok && ipNet.Contains(dstSubnetIp) {
				//log.Printf("Found interface: %s\n", iFaceTmp.Name)
				return &iFaceTmp, &ipNet.IP, nil
			}
		}
	}
	return GetDefaultIFace()
}

func GetDefaultIFace() (*net.Interface, *net.IP, error) {
	srcIp, err := GetSendIp()
	if err != nil {
		return nil, nil, err
	}
	iFaces, err := net.Interfaces()
	if err != nil {
		return nil, nil, err
	}

	for _, iFaceTmp := range iFaces {
		iFaceAdds, err := iFaceTmp.Addrs()
		if err != nil {
			log.Println(err)
			continue
		}
		for _, addr := range iFaceAdds {
			r := strings.Split(addr.String(), "/")
			if len(r) == 2 && r[0] == srcIp.String() {
				//fmt.Printf("Found interface: %s\n", iFaceTmp.Name)
				return &iFaceTmp, &srcIp, nil
			}
		}
	}
	return nil, nil, nil
}

func parseIpNet(subnet string) (*net.IPNet, error) {
	_, ipNet, err := net.ParseCIDR(subnet)
	if err == nil {
		return ipNet, nil
	}
	ip := net.ParseIP(subnet)
	if ip == nil {
		return nil, ErrInvalidAddr
	}
	return &net.IPNet{
		IP:   ip,
		Mask: net.CIDRMask(32, 32),
	}, nil
}

func ParseIpNet(target []string) ([]net.IP, error) {
	var dstIps []net.IP
	for _, v := range target {
		ipNet, err := parseIpNet(v)
		if err != nil {
			return dstIps, err
		}
		dstIps = append(dstIps, GetIpListByIPNet(ipNet)...)
	}
	return dstIps, nil
}

func GetIpListByIPNet(ipNet *net.IPNet) []net.IP {
	var ipList []net.IP
	for ip := ipNet.IP.Mask(ipNet.Mask); ipNet.Contains(ip); inc(ip) {
		//去掉网络地址和广播地址
		if ip[3] != 255 && ip[3] != 0 {
			tmpIp := net.IPv4(ip[0], ip[1], ip[2], ip[3])
			ipList = append(ipList, tmpIp)
		}
	}
	return ipList
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func parsePort(port string) (portList []uint16, err error) {
	parts := strings.Split(port, "-")
	if len(parts) > 2 || len(parts) < 1 {
		err = ErrInvalidPort
		return
	}

	startPort, err := strconv.ParseUint(parts[0], 10, 16)
	if err != nil {
		err = ErrInvalidPort
		return
	}
	if len(parts) == 1 {
		portList = append(portList, uint16(startPort))
		return
	}

	endPort, err := strconv.ParseUint(parts[1], 10, 16)
	if err != nil {
		err = ErrInvalidPort
		return
	}

	if startPort < 1 || startPort > 65535 || endPort < 1 || endPort > 65535 {
		err = ErrInvalidPort
		return
	}

	if startPort > endPort {
		err = ErrInvalidPort
		return
	}
	for i := startPort; i <= endPort; i++ {
		portList = append(portList, uint16(i))
	}
	return
}

func ParsePort(port []string) ([]uint16, error) {
	var ports []uint16
	for _, v := range port {
		tmp, err := parsePort(v)
		if err != nil {
			return ports, err
		}
		ports = append(ports, tmp...)
	}
	return ports, nil
}

func GetMac(srcIp, dstIp net.IP, srcMac net.HardwareAddr) net.HardwareAddr {
	ifs, err := pcap.FindAllDevs()
	if err != nil {
		log.Panic(err)
	}
	var device string
Loop:
	for _, dev := range ifs {
		for _, address := range dev.Addresses {
			if address.IP.String() == srcIp.String() {
				device = dev.Name
				break Loop
			}
		}
	}
	//fmt.Printf("Device name: %s\n", device)
	//fmt.Printf("Device address: %s\n", srcIp)
	//fmt.Println(flag.Args())
	r, err := netroute.New()
	if err != nil {
		panic(err)
	}
	_, gwIp, _, err := r.Route(dstIp)
	if err != nil {
		panic(err)
	}
	if gwIp == nil {
		gwIp = dstIp
	}

	//fmt.Printf("gwIp: %s\n", gwIp)
	//fmt.Printf("srcMac: %s\n", srcMac)
	handle, err := pcap.OpenLive(device, 1024, false, pcap.BlockForever)
	if err != nil {
		log.Fatalln(err)
	}
	defer handle.Close()

	eth := layers.Ethernet{
		SrcMAC:       srcMac,
		DstMAC:       layers.EthernetBroadcast,
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(srcMac),
		SourceProtAddress: []byte(srcIp),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress:    []byte(gwIp.To4()),
	}
	buf := gopacket.NewSerializeBuffer()
	ops := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	err = gopacket.SerializeLayers(buf, ops, &eth, &arp)
	if err != nil {
		panic(err)
	}
	err = handle.WritePacketData(buf.Bytes())
	if err != nil {
		panic(err)
	}
	start := time.Now()

	for {
		if time.Since(start) > time.Second*3 {
			panic(errors.New("timeout getting ARP reply"))
		}
		data, _, err := handle.ReadPacketData()
		if errors.Is(err, pcap.NextErrorTimeoutExpired) {
			continue
		} else if err != nil {
			panic(err)
		}
		packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.NoCopy)
		if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
			arp := arpLayer.(*layers.ARP)
			if net.IP(arp.SourceProtAddress).Equal(net.IP(gwIp)) {
				return arp.SourceHwAddress
			}
		}
	}

}

func FileIsExist(filename string) bool {
	_, err := os.Stat(filename)
	if err == nil || os.IsExist(err) {
		return true
	}
	return false
}

func TcpSend() {

}
