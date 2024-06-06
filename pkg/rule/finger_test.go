package rule

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log"
	"net"
	"testing"
	"time"
)

func TestSend(t *testing.T) {
	//conn, err := net.Dial("tcp", "120.195.198.50:27017")
	//if err != nil {
	//	panic(err)
	//}
	//defer conn.Close()

	srcMac, err := net.ParseMAC("")
	if err != nil {
		panic(err)
	}
	gwMac, err := net.ParseMAC("")
	if err != nil {
		panic(err)
	}
	srcIp := net.ParseIP("").To4()
	dstIp := net.ParseIP("").To4()

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

	// 打开网络接口
	handle, err := pcap.OpenLive(device, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// 以太网层
	ethLayer := &layers.Ethernet{
		SrcMAC:       srcMac,
		DstMAC:       gwMac,
		EthernetType: layers.EthernetTypeIPv4,
	}

	// IP层
	ipLayer := &layers.IPv4{
		SrcIP:    srcIp,
		DstIP:    dstIp,
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
	}

	// TCP层
	tcpLayer := &layers.TCP{
		SrcPort: 12345,
		DstPort: 27017,
		SYN:     true,
		Seq:     1105024978,
		Window:  64240,
		Options: []layers.TCPOption{
			{
				OptionType:   layers.TCPOptionKindMSS,
				OptionLength: 4,
				OptionData:   []byte{0x05, 0xb4}, // 1360
			},
			{
				OptionType: layers.TCPOptionKindNop,
			},
			{
				OptionType:   layers.TCPOptionKindWindowScale,
				OptionLength: 3,
				OptionData:   []byte{0x08},
			},
			{
				OptionType: layers.TCPOptionKindNop,
			},
			{
				OptionType: layers.TCPOptionKindNop,
			},
			{
				OptionType:   layers.TCPOptionKindSACKPermitted,
				OptionLength: 2,
			},
		},
	}
	tcpLayer.SetNetworkLayerForChecksum(ipLayer)

	// 序列化层
	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	err = gopacket.SerializeLayers(buffer, options, ethLayer, ipLayer, tcpLayer)
	if err != nil {
		log.Fatal(err)
	}

	// 发送数据包
	err = handle.WritePacketData(buffer.Bytes())
	if err != nil {
		log.Fatal(err)
	}

	// 等待回应
	time.Sleep(time.Second)

	// 发送数据包示例
	payload := []byte("Hello, Server!")
	tcpLayer.SYN = false
	tcpLayer.ACK = true
	tcpLayer.Seq = 1105024979
	tcpLayer.Ack = 1

	// 重置缓冲区
	buffer = gopacket.NewSerializeBuffer()

	err = gopacket.SerializeLayers(buffer, options, ethLayer, ipLayer, tcpLayer, gopacket.Payload(payload))
	if err != nil {
		log.Fatal(err)
	}

	err = handle.WritePacketData(buffer.Bytes())
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("数据包发送完成")
}
