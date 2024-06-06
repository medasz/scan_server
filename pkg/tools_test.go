package pkg

import (
	"fmt"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGetSendIp(t *testing.T) {
	srcIp, err := GetSendIp()
	require.NoError(t, err)
	require.NotEmpty(t, srcIp)
}

func TestGetIFace(t *testing.T) {
	iFace, iFaceIp, err := GetIFace(&net.IPNet{IP: net.IPv4(127, 0, 0, 1), Mask: net.CIDRMask(32, 32)})
	fmt.Println(iFaceIp)
	require.NoError(t, err)
	require.NotEmpty(t, iFace)
	require.NotEmpty(t, iFaceIp)
}

func TestGetDefaultIFace(t *testing.T) {
	iFace, iFaceIp, err := GetDefaultIFace()
	fmt.Println(iFaceIp)
	require.NoError(t, err)
	require.NotEmpty(t, iFace)
	require.NotEmpty(t, iFaceIp)
}

func TestParseIpNet(t *testing.T) {
	testData := []struct {
		subnet string
		result *net.IPNet
		err    error
	}{
		{
			subnet: "192.168.0.1/16",
			result: &net.IPNet{IP: net.IPv4(192, 168, 0, 0), Mask: net.IPv4Mask(255, 255, 0, 0)},
			err:    nil,
		}, {
			subnet: "10.10.80.50",
			result: &net.IPNet{IP: net.IPv4(10, 10, 80, 50), Mask: net.CIDRMask(32, 32)},
			err:    nil,
		}, {
			subnet: "10.10.80.5-20",
			result: nil,
			err:    ErrInvalidAddr,
		},
	}
	for _, v := range testData {
		subnet, err := parseIpNet(v.subnet)
		require.Equal(t, v.err, err)
		require.Equal(t, v.result.String(), subnet.String())
	}
}

func TestGetIpListByIPNet(t *testing.T) {
	ipList := GetIpListByIPNet(&net.IPNet{
		IP:   net.IPv4(10, 10, 80, 1),
		Mask: net.CIDRMask(16, 32),
	})
	require.NotEmpty(t, ipList)
	fmt.Println(ipList)
	fmt.Println(len(ipList))
	require.Len(t, ipList, 256*256-256*2)
}

func TestParsePort(t *testing.T) {
	testData := []struct {
		port      string
		expectLen int
		err       error
	}{
		{
			port:      "80",
			expectLen: 1,
			err:       nil,
		}, {
			port:      "80-88",
			expectLen: 9,
			err:       nil,
		}, {
			port:      "89-88",
			expectLen: 0,
			err:       ErrInvalidPort,
		}, {
			port:      "80-12b",
			expectLen: 0,
			err:       ErrInvalidPort,
		}, {
			port:      "asd",
			expectLen: 0,
			err:       ErrInvalidPort,
		},
	}
	for _, v := range testData {
		ports, err := parsePort(v.port)
		require.Equal(t, v.err, err)
		require.Equal(t, v.expectLen, len(ports))
	}
}

func TestNetIp(t *testing.T) {
	ip := net.IPv4(10, 10, 80, 50)
	fmt.Println(ip)
	ip1 := ip.To4()
	fmt.Println(ip1)
	ip2 := net.ParseIP("10.10.80.50").To16()
	ip3 := net.ParseIP("10.10.80.50").To4()
	fmt.Println(ip2)
	fmt.Println(ip3)
}
