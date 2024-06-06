package rule

type (
	Probe struct {
		Protocol     string       `json:"protocol"`
		Probename    string       `json:"probename"`
		Probestring  string       `json:"probestring"`
		Ports        []string     `json:"ports"`
		Sslports     []string     `json:"sslports"`
		Totalwaitms  string       `json:"totalwaitms"`
		Tcpwrappedms string       `json:"tcpwrappedms"`
		Rarity       string       `json:"rarity"`
		Fallback     string       `json:"fallback"`
		Matches      []Match      `json:"matches"`
		Softmatches  []Softmatche `json:"softmatches"`
	}
	Match struct {
		Pattern     string      `json:"pattern"`
		Name        string      `json:"name"`
		PatternFlag string      `json:"pattern_flag"`
		Versioninfo Versioninfo `json:"versioninfo"`
	}
	Softmatche struct {
		Pattern     string      `json:"pattern"`
		Name        string      `json:"name"`
		PatternFlag string      `json:"pattern_flag"`
		Versioninfo Versioninfo `json:"versioninfo"`
	}
	Versioninfo struct {
		Cpename           []CpeInfo `json:"cpename"`
		Devicetype        string    `json:"devicetype"`
		Hostname          string    `json:"hostname"`
		Info              string    `json:"info"`
		Operatingsystem   string    `json:"operatingsystem"`
		Vendorproductname string    `json:"vendorproductname"`
		Version           string    `json:"version"`
	}
	CpeInfo struct {
		Part     string `json:"part"`
		Vendor   string `json:"vendor"`
		Product  string `json:"product"`
		Version  string `json:"version"`
		Update   string `json:"update"`
		Edition  string `json:"edition"`
		Language string `json:"language"`
	}
)
