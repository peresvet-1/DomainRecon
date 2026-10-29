# DomainRecon

A Python-based reconnaissance tool for DNS analysis, subdomain enumeration, URL checks, and HTTP security header inspection.

## Features

- **DNS Scan** — retrieves A, AAAA, MX, NS, and TXT records.
- **URL Check** — sends an HTTP request and displays the response status code and final URL after redirects.
- **Subdomain Enumeration** — checks candidate subdomains from a local wordlist (`wordlists/subdomains.txt`) using A or AAAA DNS records and displays resolved IP addresses.
- **HTTP Security Analyzer** — inspects common HTTP security headers and reports missing or potentially unsafe configurations.
- **Terminal Interface** — interactive menu built with Rich.

## Requirements

- Python 3.10 or newer
- Internet connection for external DNS and HTTP checks

## Installation

Clone the repository:

```bash
git clone https://github.com/peresvet-1/DomainRecon
cd DomainRecon
```

Create and activate a virtual environment.

**Windows PowerShell:**

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

Install dependencies:

```powershell
python -m pip install -r requirements.txt
```

## Usage

Run the tool:

```powershell
python main.py
```

Choose an option from the interactive menu and provide the requested domain or URL.

## Project Structure

```text
DomainRecon/
├── main.py
├── dns_scanner.py
├── subdomain_scanner.py
├── http_security.py
├── requirements.txt
├── wordlists/
│   └── subdomains.txt
└── README.md
```

## Disclaimer

DomainRecon is intended for educational purposes and authorized security testing. Only scan domains and systems you own or have explicit permission to assess.

Missing HTTP security headers do not automatically mean a website is vulnerable. Findings should be interpreted in the context of the application and its security requirements.

## License

No license has been specified yet.