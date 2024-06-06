package scan

import (
	"log"
	"net"
	"scan_server/pkg/scan/tcp"
)

func SYNScan(dstIps []net.IP, ports []uint16) {
	for _, dstIp := range dstIps {
		for _, port := range ports {
			syn, err := tcp.NewSYNScanOpt(dstIp, port)
			if err != nil {
				log.Println(err)
				continue
			}
			syn.SYNScan()
		}
	}
}
