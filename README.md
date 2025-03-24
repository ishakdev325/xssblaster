# XSSBlaster

![XSSBlaster Logo](http://reacto.infinityfreeapp.com/image.png)

**XSSBlaster** is an advanced, multi-threaded tool designed to identify **Cross-Site Scripting (XSS)** vulnerabilities in web applications. It leverages a variety of payloads, stealth techniques, and WAF bypass methods to test for potential XSS vulnerabilities in target URLs. The tool supports detailed reporting in JSON and HTML formats, proxy usage, IP rotation, and verbose logging for debugging.

## Features

- **Multi-threaded Scanning**: Uses `ThreadPoolExecutor` to efficiently test multiple payloads concurrently.
- **Stealth Headers**: Generates randomized headers (e.g., `User-Agent`, `X-Forwarded-For`) to evade detection.
- **Payload Variety**: Includes **30+ unique XSS payloads** targeting different contexts (parameters, attributes, fuzzing).
- **WAF Bypass**: Implements encoding techniques (e.g., URL encoding, base64, UTF-16) and obfuscation to bypass Web Application Firewalls.
- **DNS Caching**: Resolves and caches target IP addresses for improved performance and IP rotation.
- **Detailed Reporting**: Saves scan results in compressed JSON format and generates an HTML report with **Tailwind CSS** styling.
- **Proxy Support**: Allows scanning through HTTP/HTTPS proxies.
- **Verbose Mode**: Provides detailed logs for debugging purposes.
- **Success Counting**: Tracks successful injections when enabled.

## Requirements

- **Python 3.6+**
- Required libraries (install via pip):

```bash
pip install requests beautifulsoup4 colorama dnspython brotli chardet urllib3 certifi
```

## Installation

1. Clone or download this repository:

```bash
git clone https://github.com/ishakdev325/xssblaster.git
cd xssblaster
```

2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. Run the tool:

```bash
python xssblaster.py -h
```

## Usage

Run **XSSBlaster** with the `-xss` flag to initiate a scan. Below are the available command-line arguments:

```bash
python xssblaster.py [target] -xss [options]
```

### Arguments

| Argument         | Description                          | Default                         |
|------------------|--------------------------------------|-------------------------------==|
| `target`         | Target URL (e.g., `example.com`)     | Required                        |
| `-xss`           | Enable XSS scanning mode             | Required                        |
| `-s`             | Delay between requests (seconds)     | `2`                             |
| `-p, --proxy`    | Proxy URL (e.g., `http://proxy:port`)| `None`                          |
| `-r, --report`   | Custom report filename               | `xssblaster_report_<uuid>.json` |
| `-t, --threads`  | Number of concurrent threads         | `5`                             |
| `-v, --verbose`  | Enable verbose logging               | `False`                         |
| `-c, --count`    | Count successful injections          | `False`                         |
=============================================================================================

### Examples

- **Basic scan**:

```bash
python xssblaster.py example.com -xss
```

- **Scan with proxy and custom delay**:

```bash
python xssblaster.py example.com -xss -p http://127.0.0.1:8080 -s 1
```

- **Verbose mode with 10 threads and custom report**:

```bash
python xssblaster.py example.com -xss -t 10 -v -r myreport.json
```

- **Enable success counting**:

```bash
python xssblaster.py example.com -xss -c
```

## Output

- **Console**: Colored output indicating scan progress, vulnerabilities, and report generation:
  - **Cyan**: Target locked
  - **Blue**: Fingerprint details
  - **Red**: Vulnerabilities found
  - **Green**: Safe targets or report saved
  - **Yellow**: Shutdown notice

- **Reports**:
  - **JSON file** (compressed with Brotli): Contains detailed scan results including vulnerabilities, timestamps, and test counts.
  - **HTML file**: Styled report using **Tailwind CSS** for easy viewing.

## How It Works

1. **Initialization**: Sets up the target URL, payloads, headers, and threading environment.
2. **Fingerprinting**: Analyzes the target page for forms, scripts, inputs, and links.
3. **Parameter Extraction**: Identifies query parameters and HTML attributes to test.
4. **Payload Testing**: Sends encoded payloads to the target, checking for reflections and execution indicators (e.g., `fetch`, `eval`).
5. **WAF Evasion**: Applies random encoding and obfuscation techniques to bypass security filters.
6. **Reporting**: Saves results and generates an HTML summary.

## Notes

- The tool disables SSL verification and `urllib3` warnings for flexibility in testing environments.
- Payloads include remote calls to `xss.st` for demonstration; replace with your own endpoints in production.
- Use responsibly and only on targets you have **permission to test**.

## License

This project is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for details.

## Contributing

Feel free to submit issues or pull requests to improve the tool. Contributions are welcome! 
