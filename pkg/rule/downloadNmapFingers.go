package rule

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"time"

	"github.com/mitchellh/go-homedir"
)

var (
	homeDir, _ = homedir.Dir()
	FingerPath = path.Join(homeDir, ".scan_server", "nmap-service-probes.txt")
)

func DownloadNmapFingers() (err error) {
	tr := &http.Transport{
		Proxy: func(*http.Request) (*url.URL, error) {
			return url.Parse("socks5://127.0.0.1:1080")
		},
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	client := &http.Client{
		Transport: tr,
		Timeout:   time.Second * 5, //超时时间
	}
	resp, err := client.Get("https://raw.githubusercontent.com/nmap/nmap/master/nmap-service-probes")
	if err != nil {
		return
	}
	defer resp.Body.Close()

	err = os.MkdirAll(path.Join(homeDir, ".scan_server"), os.ModePerm)
	if err != nil {
		return
	}
	f, err := os.OpenFile(
		FingerPath,
		os.O_CREATE|os.O_RDWR, os.ModePerm)
	if err != nil {
		return
	}
	_, err = io.Copy(f, resp.Body)
	return
}
