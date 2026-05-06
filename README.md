<div align="center">
  <img src="https://readme-typing-svg.herokuapp.com?font=JetBrains+Mono&weight=700&size=42&duration=3000&pause=800&color=FF6B00&center=true&vCenter=true&width=600&lines=pacPortScanner+Go;%E2%8A%99+Scan.+Detect.+Report." alt="pacPortScanner Go" />
</div>

## Run

Go is not currently installed on this machine. After installing Go:

```powershell
go run .
```

Headless scan:

```powershell
go run . 127.0.0.1 -p top100 --backend socket --no-cve --no-tui
```

Build:

```powershell
go build -o pacportscanner-go.exe .
```

Web UI:

```powershell
go run . web --port 43110
```

## Features

| Area | Go version |
| --- | --- |
| Setup | Prompt-based orange-on-dark setup flow |
| Scanner | Standard library TCP connect scanner |
| Backend | Auto Nmap fallback, raw maps safely to socket fallback |
| Ports | `top100`, `top1000`, `all`, lists, ranges |
| Targets | Hostname, IP, IPv4 CIDR |
| CVE | Optional NVD lookup |
| Web | Localhost web UI with setup, live polling, results, logs, export |
| Output | JSON, CSV, self-contained HTML in `./data/` |

## Safety

Built for legitimate security testing, CTFs, and learning on infrastructure you own or have written permission to test.
