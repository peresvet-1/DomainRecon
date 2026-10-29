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

### Requirements

- Python 3.10 or newer
- Git
- Internet connection

### 1. Clone the repository

```bash
git clone https://github.com/peresvet-1/DomainRecon.git
cd DomainRecon
```

### 2. Create a virtual environment

**Windows (Command Prompt):**

```bat
py -m venv .venv
```

**Windows (PowerShell):**

```powershell
py -m venv .venv
```

**Linux / Kali Linux:**

```bash
python3 -m venv .venv
```

If Linux reports that the `venv` module is unavailable, install the appropriate Python venv package for your distribution, then retry.

### 3. Activate the virtual environment

**Windows (Command Prompt):**

```bat
.venv\Scripts\activate.bat
```

**Windows (PowerShell):**

```powershell
.\.venv\Scripts\Activate.ps1
```

**Linux / Kali Linux:**

```bash
source .venv/bin/activate
```

### 4. Install dependencies

After activating the virtual environment, run:

```bash
python -m pip install -r requirements.txt
```

### 5. Run DomainRecon

```bash
python main.py
```

## Usage

Choose an option from the interactive menu.

- **DNS Scan** — retrieves A, AAAA, MX, NS, and TXT records.
- **URL Check** — displays the HTTP response status code and final URL after redirects.
- **Subdomain Enumeration** — checks candidate subdomains from `wordlists/subdomains.txt` using A or AAAA DNS records.
- **HTTP Security Analyzer** — inspects common HTTP security headers and

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