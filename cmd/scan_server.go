package cmd

import (
	"fmt"
	"net"
	"os"
	"scan_server/pkg"
	"scan_server/pkg/rule"
	"scan_server/pkg/scan"

	"github.com/spf13/cobra"
)

var (
	update, server bool
	target, port   []string
	dstIps         []net.IP
	ports          []uint16
)

func Run(version string) {
	if err := newRootCmd(version).Execute(); err != nil {
		os.Exit(1)
	}
}

func newRootCmd(version string) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "scan_server",
		Short:   "scan server",
		Version: version,
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			if update {
				fmt.Println("Updating finger...")
				return rule.DownloadNmapFingers()
			}
			fmt.Println("Scanning ip...")
			if dstIps, err = pkg.ParseIpNet(target); err != nil {
				return
			}
			if ports, err = pkg.ParsePort(port); err != nil {
				return
			}
			fmt.Println(dstIps)
			fmt.Println(ports)
			scan.SYNScan(dstIps, ports)
			return
		},
	}
	initFlag(cmd)

	return cmd
}

func initFlag(cmd *cobra.Command) {
	cmd.Flags().BoolVar(&update, "update", false, "update finger")
	cmd.Flags().BoolVarP(&server, "server", "s", false, "Probe open ports to determine service/version info")
	cmd.Flags().StringSliceVarP(&target, "target", "t", []string{}, "Scan targets:\n"+"127.0.0.1,192.168.0.1/24")
	cmd.Flags().StringSliceVarP(&port, "port", "p", []string{}, "Scan ports:"+"1-50,88,8080")
	cmd.MarkFlagRequired("target")
	cmd.MarkFlagRequired("port")
}
