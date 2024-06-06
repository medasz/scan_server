package rule

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"regexp"
	"scan_server/pkg"
	"strings"
)

var (
	Fingers = ParseNmap()
)

func In(items []string, item string) bool {
	for _, i := range items {
		if i == item {
			return true
		}
	}
	return false
}

func ParseNmap() []Probe {
	if !pkg.FileIsExist(FingerPath) {
		if err := DownloadNmapFingers(); err != nil {
			panic(err)
		}
	}
	f, err := os.Open(FingerPath)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	scan := bufio.NewScanner(f)
	var count int
	var probe Probe
	var probes []Probe
	for scan.Scan() {
		count++
		line := strings.TrimSpace(scan.Text())
		if len(line) == 0 || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "Exclude ") {
			continue
		}
		if strings.HasPrefix(line, "Probe ") {
			if probe.Protocol != "" && probe.Probename != "" {
				probes = append(probes, probe)
			}
			probe = Probe{
				Protocol:     "",
				Probename:    "",
				Probestring:  "",
				Ports:        []string{},
				Sslports:     []string{},
				Totalwaitms:  "",
				Tcpwrappedms: "",
				Rarity:       "",
				Fallback:     "",
				Matches:      []Match{},
				Softmatches:  []Softmatche{},
			}
			probe.Protocol = line[6:9]
			if !In([]string{"TCP", "UDP"}, probe.Protocol) {
				panic(errors.New(probe.Protocol + " 不支持"))
			}
			probeNameStart := 10
			probeNameEnd := strings.Index(line[probeNameStart:], " ") + probeNameStart
			if probeNameEnd-probeNameStart <= 0 {
				panic(errors.New("probename解析失败"))
			}
			probe.Probename = line[probeNameStart:probeNameEnd]

			probeStringStart := strings.Index(line[probeNameEnd:], "q|") + probeNameEnd + 1
			if probeStringStart <= probeNameEnd+1 {
				panic(errors.New("probestring解析失败"))
			}
			probe.Probestring = strings.Trim(line[probeStringStart:], "|")

			//fmt.Println(probe.Protocol, probe.Probename, probe.Probestring)
		} else if strings.HasPrefix(line, "match ") {
			matchText := line[len("match "):]
			mIndex := strings.Index(matchText, " m")
			m := matchText[mIndex+2 : mIndex+3]
			name := matchText[:mIndex]
			matchText = strings.TrimSpace(matchText[len(name):])

			//获取正则内容
			regxStart := 2
			regxEnd := strings.Index(matchText[regxStart:], m) + regxStart
			if regxEnd-regxStart <= 0 {
				panic(errors.New(fmt.Sprintf("%s：%s", "pattern解析失败：", matchText)))
			}
			regx := matchText[regxStart:regxEnd]
			var regxFlag string
			if regxEnd+1 < len(matchText) {
				regxFlag = strings.TrimSpace(matchText[regxEnd+1 : regxEnd+2])
			}
			match := Match{
				Pattern:     regx,
				Name:        name,
				PatternFlag: regxFlag,
			}
			matchText = matchText[regxEnd:]
			regxp, err := regexp.Compile(`(\w|cpe:)/(.*?)/`)
			if err != nil {
				panic(err)
			}
			ll := regxp.FindAllStringSubmatch(matchText, -1)
			for _, v := range ll {
				if len(v) < 3 {
					continue
				}
				switch v[1] {
				case "p":
					match.Versioninfo.Vendorproductname = v[2]
				case "v":
					match.Versioninfo.Version = v[2]
				case "i":
					match.Versioninfo.Info = v[2]
				case "h":
					match.Versioninfo.Hostname = v[2]
				case "o":
					match.Versioninfo.Operatingsystem = v[2]
				case "d":
					match.Versioninfo.Devicetype = v[2]
				case "cpe:":
					cpes := strings.SplitN(v[2], ":", 7)
					cpeInfo := CpeInfo{}
					for i, val := range cpes {
						switch i {
						case 0:
							cpeInfo.Part = val
						case 1:
							cpeInfo.Vendor = val
						case 2:
							cpeInfo.Product = val
						case 3:
							cpeInfo.Version = val
						case 4:
							cpeInfo.Update = val
						case 5:
							cpeInfo.Edition = val
						case 6:
							cpeInfo.Language = val
						}
					}
					match.Versioninfo.Cpename = append(match.Versioninfo.Cpename, cpeInfo)
				}
			}
			probe.Matches = append(probe.Matches, match)
		} else if strings.HasPrefix(line, "softmatch ") {
			matchText := line[len("softmatch "):]
			index := strings.Index(matchText, " m")
			m := matchText[index+2 : index+3]
			name := matchText[:index]
			matchText = strings.TrimSpace(matchText[index:])

			regxStart := 2
			regxEnd := strings.Index(matchText[regxStart:], m) + regxStart
			if regxEnd-regxStart <= 0 {
				panic(errors.New(fmt.Sprintf("%s：%s", "pattern解析失败：", matchText)))
			}
			regx := matchText[regxStart:regxEnd]
			var regxFlag string
			if regxEnd+1 < len(matchText) {
				regxFlag = strings.TrimSpace(matchText[regxEnd+1 : regxEnd+2])
			}
			softmatch := Softmatche{
				Pattern:     regx,
				Name:        name,
				PatternFlag: regxFlag,
			}
			matchText = matchText[regxEnd:]

			regxp, err := regexp.Compile(`(\w|cpe:)/(.*?)/`)
			if err != nil {
				panic(err)
			}
			ll := regxp.FindAllStringSubmatch(matchText, -1)
			for _, v := range ll {
				if len(v) < 3 {
					continue
				}
				switch v[1] {
				case "p":
					softmatch.Versioninfo.Vendorproductname = v[2]
				case "v":
					softmatch.Versioninfo.Version = v[2]
				case "i":
					softmatch.Versioninfo.Info = v[2]
				case "h":
					softmatch.Versioninfo.Hostname = v[2]
				case "o":
					softmatch.Versioninfo.Operatingsystem = v[2]
				case "d":
					softmatch.Versioninfo.Devicetype = v[2]
				case "cpe:":
					cpes := strings.SplitN(v[2], ":", 7)
					cpeInfo := CpeInfo{}
					for i, val := range cpes {
						switch i {
						case 0:
							cpeInfo.Part = val
						case 1:
							cpeInfo.Vendor = val
						case 2:
							cpeInfo.Product = val
						case 3:
							cpeInfo.Version = val
						case 4:
							cpeInfo.Update = val
						case 5:
							cpeInfo.Edition = val
						case 6:
							cpeInfo.Language = val
						}
					}
					softmatch.Versioninfo.Cpename = append(softmatch.Versioninfo.Cpename, cpeInfo)
				}
			}
			probe.Softmatches = append(probe.Softmatches, softmatch)
		} else if strings.HasPrefix(line, "ports ") {
			ports := strings.Split(line[len("ports "):], ",")
			probe.Ports = ports
		} else if strings.HasPrefix(line, "sslports ") {
			sslports := strings.Split(line[len("sslports "):], ",")
			probe.Sslports = sslports
		} else if strings.HasPrefix(line, "totalwaitms ") {
			totalwaitms := line[len("totalwaitms "):]
			probe.Totalwaitms = totalwaitms
		} else if strings.HasPrefix(line, "tcpwrappedms ") {
			tcpwrappedms := line[len("tcpwrappedms "):]
			probe.Tcpwrappedms = tcpwrappedms
		} else if strings.HasPrefix(line, "rarity ") {
			rarity := line[len("rarity "):]
			probe.Rarity = rarity
		} else if strings.HasPrefix(line, "fallback ") {
			fallback := line[len("fallback "):]
			probe.Fallback = fallback
		} else {
			println("[x] ", line)
		}
	}
	if probe.Protocol != "" && probe.Probename != "" {
		probes = append(probes, probe)
	}
	//buffer := &bytes.Buffer{}
	//encoder := json.NewEncoder(buffer)
	//encoder.SetEscapeHTML(false)
	//encoder.SetIndent("", "	")
	//err = encoder.Encode(probes)
	//if err != nil {
	//	panic(err)
	//}
	//fi, err := os.OpenFile("res.json", os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)
	//if err != nil {
	//	panic(err)
	//}
	//fi.Write(buffer.Bytes())
	//defer fi.Close()
	return probes
}
