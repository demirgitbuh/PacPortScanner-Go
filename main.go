package main

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"errors"
	"flag"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	version = "0.1.0"
	orange = "\033[38;2;255;107;0m"
	dim    = "\033[90m"
	reset  = "\033[0m"
)

type ProfileName string
type BackendPreference string
type BackendName string
type PortState string

const (
	ProfileStealth       ProfileName = "stealth"
	ProfileFast          ProfileName = "fast"
	ProfileFull          ProfileName = "full"
	ProfileVulnerability ProfileName = "vulnerability"

	BackendAuto   BackendPreference = "auto"
	BackendNmap   BackendPreference = "nmap"
	BackendRaw    BackendPreference = "raw"
	BackendSocket BackendPreference = "socket"

	BackendNameNmap   BackendName = "nmap"
	BackendNameRaw    BackendName = "raw"
	BackendNameSocket BackendName = "socket"

	StateOpen     PortState = "open"
	StateClosed   PortState = "closed"
	StateFiltered PortState = "filtered"
)

type Profile struct {
	Ports            string
	Timeout          float64
	Concurrency      int
	PingSweep        bool
	CVELookup        bool
	ServiceDetection bool
	BannerGrab       bool
	OSDetection      bool
	Technique        string
}

type CVEFinding struct {
	ID       string  `json:"id"`
	Title    string  `json:"title,omitempty"`
	Severity string  `json:"severity"`
	Score    float64 `json:"score,omitempty"`
	Source   string  `json:"source"`
	URL      string  `json:"url"`
}

type PortResult struct {
	Host     string       `json:"host"`
	Port     int          `json:"port"`
	Protocol string       `json:"protocol"`
	State    PortState    `json:"state"`
	Service  string       `json:"service,omitempty"`
	Version  string       `json:"version,omitempty"`
	Banner   string       `json:"banner,omitempty"`
	CPES     []string     `json:"cpes,omitempty"`
	CVES     []CVEFinding `json:"cves,omitempty"`
	OS       string       `json:"os,omitempty"`
	TTL      int          `json:"ttl,omitempty"`
}

type ScanConfig struct {
	Targets          []string          `json:"targets"`
	Ports            []int             `json:"ports"`
	PortsSpec        string            `json:"portsSpec"`
	Profile          ProfileName       `json:"profile"`
	Backend          BackendPreference `json:"backend"`
	Concurrency      int               `json:"concurrency"`
	Timeout          float64           `json:"timeout"`
	PingSweep        bool              `json:"pingSweep"`
	CVELookup        bool              `json:"cveLookup"`
	ServiceDetection bool              `json:"serviceDetection"`
	BannerGrab       bool              `json:"bannerGrab"`
	OSDetection      bool              `json:"osDetection"`
}

type Snapshot struct {
	Status    string        `json:"status"`
	Backend   BackendName   `json:"backend"`
	Processed int           `json:"processed"`
	Total     int           `json:"total"`
	Results   []PortResult  `json:"results"`
	Logs      []string      `json:"logs"`
	Exports   *ExportPaths  `json:"exports,omitempty"`
	Error     string        `json:"error,omitempty"`
	Config    *ScanConfig   `json:"config,omitempty"`
}

type ExportPaths struct {
	JSON string `json:"json"`
	CSV  string `json:"csv"`
	HTML string `json:"html"`
}

var profiles = map[ProfileName]Profile{
	ProfileStealth:       {Ports: "top100", Timeout: 2, Concurrency: 100, PingSweep: true, CVELookup: false, ServiceDetection: true, BannerGrab: false, OSDetection: false, Technique: "SYN if available, slow timing"},
	ProfileFast:          {Ports: "top100", Timeout: 1, Concurrency: 500, PingSweep: false, CVELookup: false, ServiceDetection: true, BannerGrab: false, OSDetection: false, Technique: "connect scan, aggressive timing"},
	ProfileFull:          {Ports: "1-65535", Timeout: 1.5, Concurrency: 500, PingSweep: false, CVELookup: false, ServiceDetection: true, BannerGrab: true, OSDetection: false, Technique: "connect scan + service + banner grab"},
	ProfileVulnerability: {Ports: "top1000", Timeout: 2, Concurrency: 300, PingSweep: true, CVELookup: true, ServiceDetection: true, BannerGrab: true, OSDetection: true, Technique: "full + OS detect + CVE lookup"},
}

var top100 = []int{7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113, 119, 135, 139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514, 515, 543, 544, 548, 554, 587, 631, 646, 873, 990, 993, 995, 1025, 1026, 1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900, 2000, 2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051, 5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001, 6646, 7070, 8000, 8008, 8009, 8080, 8081, 8443, 8888, 9100, 9999, 10000, 32768, 49152, 49153, 49154, 49155, 49156, 49157}

var serviceByPort = map[int]string{21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "domain", 80: "http", 110: "pop3", 135: "msrpc", 139: "netbios-ssn", 143: "imap", 389: "ldap", 443: "https", 445: "microsoft-ds", 465: "smtps", 587: "submission", 993: "imaps", 995: "pop3s", 1433: "mssql", 2049: "nfs", 3000: "node-dev", 3306: "mysql", 3389: "rdp", 5432: "postgresql", 5900: "vnc", 6379: "redis", 8000: "http-alt", 8008: "http-alt", 8080: "http-proxy", 8081: "http-alt", 8443: "https-alt", 9200: "elasticsearch", 27017: "mongodb"}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "web" {
		runWebCommand(os.Args[2:])
		return
	}
	if len(os.Args) > 1 && (os.Args[1] == "--version" || os.Args[1] == "-V") {
		fmt.Println(version)
		return
	}
	config, noTUI, err := parseScanArgs(os.Args[1:])
	if err != nil {
		fatal(err)
	}
	if len(config.Targets) == 0 && !noTUI {
		config, err = promptSetup()
		if err != nil {
			fatal(err)
		}
	}
	if len(config.Targets) == 0 {
		config.Targets = []string{"127.0.0.1"}
	}
	if err := runHeadless(config); err != nil {
		fatal(err)
	}
}

func runWebCommand(args []string) {
	fs := flag.NewFlagSet("web", flag.ExitOnError)
	port := fs.Int("port", 43110, "localhost port")
	host := fs.String("host", "127.0.0.1", "bind host")
	_ = fs.Parse(args)
	url, err := startWeb(*host, *port)
	if err != nil {
		fatal(err)
	}
	fmt.Println("pacPortScanner Go web UI:", url)
	fmt.Println("Press Ctrl+C to stop.")
	select {}
}

func parseScanArgs(args []string) (ScanConfig, bool, error) {
	fs := flag.NewFlagSet("pacportscanner-go", flag.ExitOnError)
	portsSpec := fs.String("ports", "", "ports")
	fs.StringVar(portsSpec, "p", "", "ports")
	profileText := fs.String("profile", "fast", "profile")
	backendText := fs.String("backend", "auto", "backend")
	noCVE := fs.Bool("no-cve", false, "disable CVE lookup")
	noTUI := fs.Bool("no-tui", false, "headless")
	if err := fs.Parse(args); err != nil {
		return ScanConfig{}, false, err
	}
	profileName := ProfileName(*profileText)
	profile, ok := profiles[profileName]
	if !ok {
		return ScanConfig{}, false, fmt.Errorf("unknown profile: %s", *profileText)
	}
	if *portsSpec == "" {
		*portsSpec = profile.Ports
	}
	ports, err := parsePorts(*portsSpec)
	if err != nil {
		return ScanConfig{}, false, err
	}
	return ScanConfig{
		Targets:          fs.Args(),
		Ports:            ports,
		PortsSpec:        *portsSpec,
		Profile:          profileName,
		Backend:          BackendPreference(*backendText),
		Concurrency:      profile.Concurrency,
		Timeout:          profile.Timeout,
		PingSweep:        profile.PingSweep,
		CVELookup:        profile.CVELookup && !*noCVE,
		ServiceDetection: profile.ServiceDetection,
		BannerGrab:       profile.BannerGrab,
		OSDetection:      profile.OSDetection,
	}, *noTUI, nil
}

func promptSetup() (ScanConfig, error) {
	fmt.Println(orange + "pacPortScanner Go setup" + reset)
	target := prompt("Target / IP", "127.0.0.1")
	profileName := ProfileName(prompt("Profile", "fast"))
	profile, ok := profiles[profileName]
	if !ok {
		profileName, profile = ProfileFast, profiles[ProfileFast]
	}
	portsSpec := prompt("Ports", profile.Ports)
	ports, err := parsePorts(portsSpec)
	if err != nil {
		return ScanConfig{}, err
	}
	timeout, _ := strconv.ParseFloat(prompt("Timeout", fmt.Sprintf("%.1f", profile.Timeout)), 64)
	concurrency, _ := strconv.Atoi(prompt("Concurrency", strconv.Itoa(profile.Concurrency)))
	return ScanConfig{
		Targets:          []string{target},
		Ports:            ports,
		PortsSpec:        portsSpec,
		Profile:          profileName,
		Backend:          BackendPreference(prompt("Backend", "auto")),
		Concurrency:      clamp(concurrency, 1, 500),
		Timeout:          timeout,
		PingSweep:        promptBool("Ping sweep", profile.PingSweep),
		CVELookup:        promptBool("CVE lookup", profile.CVELookup),
		ServiceDetection: promptBool("Service detect", profile.ServiceDetection),
		BannerGrab:       promptBool("Banner grab", profile.BannerGrab),
		OSDetection:      promptBool("OS detect", profile.OSDetection),
	}, nil
}

func prompt(label, def string) string {
	fmt.Printf("%s%s%s [%s]: ", orange, label, reset, def)
	var value string
	_, _ = fmt.Scanln(&value)
	if strings.TrimSpace(value) == "" {
		return def
	}
	return value
}

func promptBool(label string, def bool) bool {
	defText := "n"
	if def {
		defText = "y"
	}
	return strings.HasPrefix(strings.ToLower(prompt(label+" (y/n)", defText)), "y")
}

func runHeadless(config ScanConfig) error {
	backend, results, logs, err := scan(context.Background(), config)
	for _, log := range logs {
		fmt.Println(dim + log + reset)
	}
	if err != nil {
		return err
	}
	fmt.Printf("pacPortScanner Go backend=%s profile=%s\n", backend, config.Profile)
	for _, result := range results {
		if result.State == StateOpen {
			fmt.Printf("%s:%d/tcp open %s %s\n", result.Host, result.Port, result.Service, result.Version)
		}
	}
	paths, err := exportAll(backend, config, results)
	if err != nil {
		return err
	}
	fmt.Println("Exported JSON:", paths.JSON)
	fmt.Println("Exported CSV:", paths.CSV)
	fmt.Println("Exported HTML:", paths.HTML)
	return nil
}

func scan(ctx context.Context, config ScanConfig) (BackendName, []PortResult, []string, error) {
	backend := selectBackend(config.Backend)
	logs := []string{"Using " + string(backend) + " backend."}
	var results []PortResult
	var err error
	if backend == BackendNameNmap {
		results, err = scanNmap(ctx, config)
		if err != nil {
			logs = append(logs, "Nmap failed, falling back to socket: "+err.Error())
			backend = BackendNameSocket
			results, err = scanSocket(ctx, config)
		}
	} else {
		results, err = scanSocket(ctx, config)
	}
	if config.CVELookup {
		for i := range results {
			if results[i].State == StateOpen && results[i].Service != "" {
				results[i].CVES = lookupCVEs(ctx, results[i].Service, results[i].Version)
			}
		}
	}
	return backend, results, logs, err
}

func selectBackend(pref BackendPreference) BackendName {
	switch pref {
	case BackendNmap:
		return BackendNameNmap
	case BackendRaw:
		return BackendNameSocket
	case BackendSocket:
		return BackendNameSocket
	default:
		if _, err := exec.LookPath("nmap"); err == nil {
			return BackendNameNmap
		}
		return BackendNameSocket
	}
}

func scanSocket(ctx context.Context, config ScanConfig) ([]PortResult, error) {
	hosts, err := expandTargets(config.Targets)
	if err != nil {
		return nil, err
	}
	type job struct{ host string; port int }
	jobs := make(chan job)
	results := make(chan PortResult)
	var wg sync.WaitGroup
	workers := clamp(config.Concurrency, 1, 500)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				results <- scanPort(ctx, j.host, j.port, config.Timeout, config.BannerGrab)
			}
		}()
	}
	go func() {
		for _, host := range hosts {
			for _, port := range config.Ports {
				jobs <- job{host: host, port: port}
			}
		}
		close(jobs)
		wg.Wait()
		close(results)
	}()
	var out []PortResult
	for result := range results {
		out = append(out, result)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Host == out[j].Host {
			return out[i].Port < out[j].Port
		}
		return out[i].Host < out[j].Host
	})
	return out, nil
}

func scanPort(ctx context.Context, host string, port int, timeoutSecs float64, bannerGrab bool) PortResult {
	timeout := time.Duration(timeoutSecs * float64(time.Second))
	if timeout < 100*time.Millisecond {
		timeout = 100 * time.Millisecond
	}
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		state := StateFiltered
		if strings.Contains(strings.ToLower(err.Error()), "refused") {
			state = StateClosed
		}
		return baseResult(host, port, state)
	}
	defer conn.Close()
	result := baseResult(host, port, StateOpen)
	result.Service = serviceByPort[port]
	if bannerGrab {
		_ = conn.SetDeadline(time.Now().Add(1200 * time.Millisecond))
		if isHTTPLike(port) {
			_, _ = conn.Write([]byte("HEAD / HTTP/1.0\r\nUser-Agent: pacPortScanner-go\r\n\r\n"))
		}
		buffer := make([]byte, 512)
		n, _ := conn.Read(buffer)
		if n > 0 {
			result.Banner = strings.Join(strings.Fields(string(buffer[:n])), " ")
			if len(result.Banner) > 300 {
				result.Banner = result.Banner[:300]
			}
		}
	}
	return result
}

func baseResult(host string, port int, state PortState) PortResult {
	return PortResult{Host: host, Port: port, Protocol: "tcp", State: state}
}

func scanNmap(ctx context.Context, config ScanConfig) ([]PortResult, error) {
	args := []string{"-oX", "-", "-p", joinInts(config.Ports), "--reason"}
	if !config.PingSweep {
		args = append(args, "-Pn")
	}
	if config.ServiceDetection || config.BannerGrab {
		args = append(args, "-sV")
	}
	args = append(args, config.Targets...)
	cmd := exec.CommandContext(ctx, "nmap", args...)
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	return parseNmap(output)
}

type nmapRun struct {
	Hosts []nmapHost `xml:"host"`
}
type nmapHost struct {
	Addresses []struct{ Addr string `xml:"addr,attr"` } `xml:"address"`
	Ports     []nmapPort `xml:"ports>port"`
	OSMatches []struct{ Name string `xml:"name,attr"` } `xml:"os>osmatch"`
}
type nmapPort struct {
	Protocol string `xml:"protocol,attr"`
	PortID   int    `xml:"portid,attr"`
	State    struct{ State string `xml:"state,attr"` } `xml:"state"`
	Service  struct {
		Name      string   `xml:"name,attr"`
		Product   string   `xml:"product,attr"`
		Version   string   `xml:"version,attr"`
		ExtraInfo string   `xml:"extrainfo,attr"`
		CPES      []string `xml:"cpe"`
	} `xml:"service"`
}

func parseNmap(data []byte) ([]PortResult, error) {
	var doc nmapRun
	if err := xml.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	var results []PortResult
	for _, host := range doc.Hosts {
		addr := "unknown"
		if len(host.Addresses) > 0 {
			addr = host.Addresses[0].Addr
		}
		osName := ""
		if len(host.OSMatches) > 0 {
			osName = host.OSMatches[0].Name
		}
		for _, port := range host.Ports {
			state := StateFiltered
			if port.State.State == "open" {
				state = StateOpen
			} else if port.State.State == "closed" {
				state = StateClosed
			}
			version := strings.TrimSpace(strings.Join([]string{port.Service.Product, port.Service.Version, port.Service.ExtraInfo}, " "))
			results = append(results, PortResult{Host: addr, Port: port.PortID, Protocol: defaultString(port.Protocol, "tcp"), State: state, Service: port.Service.Name, Version: version, CPES: port.Service.CPES, OS: osName})
		}
	}
	return results, nil
}

func lookupCVEs(ctx context.Context, service, version string) []CVEFinding {
	query := strings.TrimSpace(service + " " + version)
	if query == "" {
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch="+strings.ReplaceAll(query, " ", "%20"), nil)
	if err != nil {
		return nil
	}
	req.Header.Set("user-agent", "pacPortScanner-go/0.1")
	client := http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	var body struct {
		Vulnerabilities []struct {
			CVE struct {
				ID           string `json:"id"`
				Descriptions []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"descriptions"`
			} `json:"cve"`
		} `json:"vulnerabilities"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil
	}
	var out []CVEFinding
	for _, item := range body.Vulnerabilities {
		title := item.CVE.ID
		for _, desc := range item.CVE.Descriptions {
			if desc.Lang == "en" {
				title = desc.Value
				break
			}
		}
		if len(title) > 180 {
			title = title[:180]
		}
		out = append(out, CVEFinding{ID: item.CVE.ID, Title: title, Severity: "UNKNOWN", Source: "nvd", URL: "https://nvd.nist.gov/vuln/detail/" + item.CVE.ID})
		if len(out) >= 10 {
			break
		}
	}
	return out
}

func exportAll(backend BackendName, config ScanConfig, results []PortResult) (ExportPaths, error) {
	if err := os.MkdirAll("data", 0755); err != nil {
		return ExportPaths{}, err
	}
	stamp := time.Now().Format("20060102_150405")
	paths := ExportPaths{JSON: filepath.Join("data", "pacportscanner_"+stamp+".json"), CSV: filepath.Join("data", "pacportscanner_"+stamp+".csv"), HTML: filepath.Join("data", "pacportscanner_"+stamp+".html")}
	doc := map[string]any{"tool": "pacPortScanner Go", "generated_at": time.Now().UTC().Format(time.RFC3339), "backend": backend, "config": config, "summary": summarize(results), "results": results}
	jsonFile, err := os.Create(paths.JSON)
	if err != nil {
		return paths, err
	}
	if err := json.NewEncoder(jsonFile).Encode(doc); err != nil {
		_ = jsonFile.Close()
		return paths, err
	}
	_ = jsonFile.Close()
	csvFile, err := os.Create(paths.CSV)
	if err != nil {
		return paths, err
	}
	writer := csv.NewWriter(csvFile)
	_ = writer.Write([]string{"host", "port", "protocol", "state", "service", "version", "banner", "os", "cves"})
	for _, result := range results {
		_ = writer.Write([]string{result.Host, strconv.Itoa(result.Port), result.Protocol, string(result.State), result.Service, result.Version, result.Banner, result.OS, joinCVEs(result.CVES)})
	}
	writer.Flush()
	_ = csvFile.Close()
	return paths, os.WriteFile(paths.HTML, []byte(renderHTML(backend, config, results)), 0644)
}

func summarize(results []PortResult) map[string]int {
	summary := map[string]int{"total": len(results), "open": 0, "closed": 0, "filtered": 0, "with_cves": 0}
	for _, result := range results {
		summary[string(result.State)]++
		if len(result.CVES) > 0 {
			summary["with_cves"]++
		}
	}
	return summary
}

func renderHTML(backend BackendName, config ScanConfig, results []PortResult) string {
	var rows strings.Builder
	for _, result := range results {
		rows.WriteString(fmt.Sprintf("<tr class=%q><td>%s</td><td>%d/tcp</td><td>%s</td><td>%s</td><td>%s</td></tr>", result.State, html.EscapeString(result.Host), result.Port, result.State, html.EscapeString(result.Service), html.EscapeString(firstNonEmpty(result.Version, result.Banner))))
	}
	return `<!doctype html><html><head><meta charset="utf-8"><title>pacPortScanner Go</title><style>body{margin:0;background:#0B0D10;color:#F4F1ED;font-family:system-ui}header{padding:32px;background:#11151b;border-bottom:1px solid #2A2F37}h1,th{color:#FF6B00}main{padding:24px}table{width:100%;border-collapse:collapse}td,th{padding:10px;border-bottom:1px solid #2A2F37;text-align:left}.open td:first-child{border-left:4px solid #FF6B00}.muted{color:#9CA3AF}</style></head><body><header><h1>pacPortScanner Go</h1><p class=muted>` + html.EscapeString(string(backend)) + ` backend, ` + html.EscapeString(string(config.Profile)) + ` profile</p></header><main><table><thead><tr><th>Host</th><th>Port</th><th>State</th><th>Service</th><th>Version / Banner</th></tr></thead><tbody>` + rows.String() + `</tbody></table></main></body></html>`
}

type webState struct {
	mu       sync.Mutex
	snapshot Snapshot
}

func startWeb(host string, port int) (string, error) {
	state := &webState{snapshot: Snapshot{Status: "idle", Backend: BackendNameSocket, Logs: []string{"Ready. Local web UI is listening on 127.0.0.1 only."}}}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, webHTML)
	})
	mux.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
		state.mu.Lock()
		defer state.mu.Unlock()
		writeJSON(w, state.snapshot)
	})
	mux.HandleFunc("/api/scan", func(w http.ResponseWriter, r *http.Request) {
		var config ScanConfig
		if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if len(config.Targets) == 0 {
			http.Error(w, "target required", http.StatusBadRequest)
			return
		}
		go func() {
			state.mu.Lock()
			state.snapshot = Snapshot{Status: "running", Backend: BackendNameSocket, Config: &config, Total: len(config.Targets) * len(config.Ports), Logs: []string{"Starting scan."}}
			state.mu.Unlock()
			backend, results, logs, err := scan(context.Background(), config)
			state.mu.Lock()
			defer state.mu.Unlock()
			state.snapshot.Backend = backend
			state.snapshot.Results = results
			state.snapshot.Processed = len(results)
			state.snapshot.Logs = append(state.snapshot.Logs, logs...)
			if err != nil {
				state.snapshot.Status = "error"
				state.snapshot.Error = err.Error()
			} else {
				state.snapshot.Status = "complete"
				state.snapshot.Logs = append(state.snapshot.Logs, "Scan complete.")
			}
		}()
		writeJSON(w, map[string]string{"ok": "true"})
	})
	mux.HandleFunc("/api/export", func(w http.ResponseWriter, r *http.Request) {
		state.mu.Lock()
		snap := state.snapshot
		state.mu.Unlock()
		if snap.Config == nil {
			http.Error(w, "no scan config", http.StatusBadRequest)
			return
		}
		paths, err := exportAll(snap.Backend, *snap.Config, snap.Results)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, paths)
	})
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return "", err
	}
	go func() { _ = http.Serve(listener, mux) }()
	return "http://" + listener.Addr().String(), nil
}

var webHTML = `<!doctype html><html><head><meta charset="utf-8"><title>pacPortScanner Go Web</title><style>body{margin:0;background:#0B0D10;color:#F4F1ED;font-family:system-ui}.app{display:grid;grid-template-columns:360px 1fr;min-height:100vh}.setup{background:#0E1217;border-right:1px solid #2A2F37;padding:16px}h1,th,strong{color:#FF6B00}input,select,button{width:100%;padding:8px;margin:5px 0;background:#15191f;color:#F4F1ED;border:1px solid #2A2F37;border-radius:8px}.primary{background:#FF6B00;color:#111;font-weight:700}.main{padding:16px}table{width:100%;border-collapse:collapse}td,th{border-bottom:1px solid #2A2F37;padding:9px;text-align:left}.muted{color:#9CA3AF}</style></head><body><div class=app><aside class=setup><h1>pacPortScanner Go</h1><input id=target value=127.0.0.1><input id=ports value=top100><select id=profile><option>stealth</option><option selected>fast</option><option>full</option><option>vulnerability</option></select><select id=backend><option selected>auto</option><option>nmap</option><option>raw</option><option>socket</option></select><input id=timeout value=1><input id=concurrency value=500><button class=primary onclick=start()>Start</button><button onclick=exportReports()>Export</button><p class=muted>Localhost web UI, orange-on-dark.</p></aside><main class=main><h1>Status: <span id=status>idle</span></h1><p>Backend: <strong id=backendText>socket</strong> Progress: <strong id=progress>0/0</strong></p><table><thead><tr><th>Host</th><th>Port</th><th>State</th><th>Service</th><th>Version / Banner</th></tr></thead><tbody id=rows></tbody></table><h2>Live Log</h2><pre id=logs class=muted></pre></main></div><script>function cfg(){let p=document.getElementById('ports').value;let ports=p==='top100'?[7,9,13,21,22,23,25,53,80,110,135,139,143,389,443,445,587,993,995,1433,3000,3306,3389,5432,5900,6379,8000,8080,8443]:p.split(',').map(Number);return{targets:[target.value],ports:ports,portsSpec:p,profile:profile.value,backend:backend.value,timeout:Number(timeout.value),concurrency:Number(concurrency.value),pingSweep:false,cveLookup:false,serviceDetection:true,bannerGrab:false,osDetection:false}}async function start(){await fetch('/api/scan',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(cfg())})}async function exportReports(){await fetch('/api/export',{method:'POST'})}function esc(v){return String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}async function tick(){let s=await(await fetch('/api/status')).json();status.textContent=s.status;backendText.textContent=s.backend;progress.textContent=s.processed+'/'+s.total;rows.innerHTML=(s.results||[]).map(r=>`<tr><td>${esc(r.host)}</td><td>${r.port}/tcp</td><td>${esc(r.state)}</td><td>${esc(r.service||'')}</td><td>${esc(r.version||r.banner||'')}</td></tr>`).join('');logs.textContent=(s.logs||[]).join('\n')}setInterval(tick,800);tick()</script></body></html>`

func parsePorts(spec string) ([]int, error) {
	spec = strings.TrimSpace(strings.ToLower(spec))
	if spec == "top100" {
		return append([]int{}, top100...), nil
	}
	if spec == "top1000" {
		ports := append([]int{}, top100...)
		for i := 1; i <= 1000; i++ {
			ports = append(ports, i)
		}
		return uniqueSorted(ports)[:1000], nil
	}
	if spec == "all" {
		ports := make([]int, 65535)
		for i := range ports {
			ports[i] = i + 1
		}
		return ports, nil
	}
	var ports []int
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "-") {
			pieces := strings.SplitN(part, "-", 2)
			start, err := parsePort(pieces[0])
			if err != nil {
				return nil, err
			}
			end, err := parsePort(pieces[1])
			if err != nil {
				return nil, err
			}
			if start > end {
				return nil, errors.New("descending port range")
			}
			for port := start; port <= end; port++ {
				ports = append(ports, port)
			}
		} else {
			port, err := parsePort(part)
			if err != nil {
				return nil, err
			}
			ports = append(ports, port)
		}
	}
	if len(ports) == 0 {
		return nil, errors.New("empty port list")
	}
	return uniqueSorted(ports), nil
}

func parsePort(value string) (int, error) {
	port, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || port < 1 || port > 65535 {
		return 0, fmt.Errorf("invalid port: %s", value)
	}
	return port, nil
}

func uniqueSorted(values []int) []int {
	sort.Ints(values)
	out := values[:0]
	last := -1
	for _, value := range values {
		if value != last {
			out = append(out, value)
			last = value
		}
	}
	return out
}

func expandTargets(targets []string) ([]string, error) {
	var out []string
	for _, target := range targets {
		expanded, err := expandTarget(target)
		if err != nil {
			return nil, err
		}
		out = append(out, expanded...)
	}
	return out, nil
}

func expandTarget(target string) ([]string, error) {
	if !strings.Contains(target, "/") {
		return []string{target}, nil
	}
	ip, network, err := net.ParseCIDR(target)
	if err != nil {
		return nil, err
	}
	ip = ip.To4()
	if ip == nil {
		return nil, errors.New("only IPv4 CIDR is supported")
	}
	var out []string
	for current := ip.Mask(network.Mask); network.Contains(current); incIP(current) {
		copyIP := append(net.IP(nil), current...)
		out = append(out, copyIP.String())
		if len(out) > 65536 {
			return nil, errors.New("CIDR expands to too many hosts")
		}
	}
	if len(out) > 2 {
		out = out[1 : len(out)-1]
	}
	return out, nil
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func isHTTPLike(port int) bool {
	switch port {
	case 80, 443, 3000, 8000, 8008, 8080, 8081, 8443, 9000:
		return true
	default:
		return false
	}
}

func joinInts(values []int) string {
	parts := make([]string, len(values))
	for i, value := range values {
		parts[i] = strconv.Itoa(value)
	}
	return strings.Join(parts, ",")
}

func joinCVEs(cves []CVEFinding) string {
	parts := make([]string, len(cves))
	for i, cve := range cves {
		parts[i] = cve.ID
	}
	return strings.Join(parts, ";")
}

func writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("content-type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}

func defaultString(value, def string) string {
	if value == "" {
		return def
	}
	return value
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func clamp(value, minValue, maxValue int) int {
	if value < minValue {
		return minValue
	}
	if value > maxValue {
		return maxValue
	}
	return value
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
