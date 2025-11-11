#!/usr/bin/env python3

import requests
import json
import os
import sys
import threading
import time
import subprocess
from datetime import datetime, timedelta
import argparse
from tabulate import tabulate
import re
from urllib.parse import urlparse, urljoin
import socket
import ssl
import dns.resolver
import whois
from concurrent.futures import ThreadPoolExecutor
import hashlib
import base64
from pathlib import Path
import yaml
import sqlite3
import asyncio
import aiohttp
from bs4 import BeautifulSoup
import shodan

# Colors for terminal output
class Colors:
    BLUE = "\033[94m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    PURPLE = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"
    RESET = "\033[0m"

class Database:
    def __init__(self):
        self.db_path = "cve.db"
        self.init_db()
    
    def init_db(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cves (
                id TEXT PRIMARY KEY,
                score REAL,
                published TEXT,
                description TEXT,
                refs TEXT,
                exploits TEXT,
                tags TEXT,
                cached_at TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS targets (
                domain TEXT PRIMARY KEY,
                technologies TEXT,
                security_headers TEXT,
                subdomains TEXT,
                ports TEXT,
                last_scan TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def cache_cve(self, cve_data):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO cves 
            (id, score, published, description, references, exploits, tags, cached_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            cve_data['id'],
            cve_data.get('score', 0),
            cve_data.get('published', ''),
            cve_data.get('description', ''),
            json.dumps(cve_data.get('references', [])),
            json.dumps(cve_data.get('exploits', [])),
            json.dumps(cve_data.get('tags', [])),
            datetime.now().isoformat()
        ))
        
        conn.commit()
        conn.close()

class CVEHunterX:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'CVE-Hunter-X/2.0 (Advanced Bug Bounty Research Platform)'
        })
        self.db = Database()
        self.config = self.load_config()
        self.shodan_api = None
        if self.config.get('shodan_api_key'):
            self.shodan_api = shodan.Shodan(self.config['shodan_api_key'])
    
    def load_config(self):
        config_file = "config.yaml"  # Bisa diganti sesuai selera bosku
        default_config = {
            'shodan_api_key': '',
            'github_token': '',
            'user_agents': [
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
                'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
            ],
            'wordlists': {
                'subdomains': ['www', 'api', 'admin', 'dev', 'staging', 'test'],
                'endpoints': ['/admin', '/.env', '/config', '/debug', '/api/v1']
            }
        }
        
        if os.path.exists(config_file):
            with open(config_file, 'r') as f:
                return yaml.safe_load(f)
        
        with open(config_file, 'w') as f:
            yaml.dump(default_config, f)
        
        return default_config
    
    def display_banner(self):
        banner = f"""
{Colors.CYAN}╔══════════════════════════════════════════════════════════════════════════════╗
║                              CVE HUNTER X v2.0                               ║
║                    Advanced Bug Bounty Research Platform                     ║
║                          The Ultimate CVE Weaponizer                         ║
╚══════════════════════════════════════════════════════════════════════════════╝{Colors.RESET}

{Colors.YELLOW}🔥 FITUR TERBARU:{Colors.RESET}
• Multi-Threading CVE Discovery    • GitHub PoC Hunter         • Shodan Integration
• Advanced Recon Suite            • Technology Stack Detector  • Auto Report Generator  
• Subdomain Enumeration           • Port Scanner & Banner Grab • Vulnerability Timeline
• Security Headers Analysis       • Domain Intelligence        • CVE Impact Calculator
        """
        print(banner)
    
    async def fetch_cve_async(self, session, cve_id):
        """Async CVE fetching for better performance"""
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0"
        params = {'cveId': cve_id}
        
        try:
            async with session.get(url, params=params) as response:
                data = await response.json()
                return data
        except Exception as e:
            return None
    
    def get_recent_cves_advanced(self, days=7, min_score=7.0, keywords=None):
        """Advanced CVE fetching with filtering"""
        print(f"{Colors.YELLOW}[*] 🚀 Advanced CVE Discovery (Score ≥{min_score})...{Colors.RESET}")
        
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)
        
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        params = {
            'pubStartDate': start_date.strftime('%Y-%m-%dT%H:%M:%S.000'),
            'pubEndDate': end_date.strftime('%Y-%m-%dT%H:%M:%S.000'),
            'resultsPerPage': 100
        }
        
        if keywords:
            params['keywordSearch'] = keywords
        
        try:
            response = self.session.get(url, params=params, timeout=30)
            response.raise_for_status()
            data = response.json()
            
            high_risk_cves = []
            for cve in data.get('vulnerabilities', []):
                cve_data = cve['cve']
                
                # Extract comprehensive CVE info
                cvss_score = 0
                vector = "N/A"
                severity = "UNKNOWN"
                
                if 'metrics' in cve_data:
                    if 'cvssMetricV31' in cve_data['metrics']:
                        metric = cve_data['metrics']['cvssMetricV31'][0]
                        cvss_score = metric['cvssData']['baseScore']
                        vector = metric['cvssData']['vectorString']
                        severity = metric['cvssData']['baseSeverity']
                    elif 'cvssMetricV30' in cve_data['metrics']:
                        metric = cve_data['metrics']['cvssMetricV30'][0]
                        cvss_score = metric['cvssData']['baseScore']
                        vector = metric['cvssData']['vectorString']
                        severity = metric['cvssData']['baseSeverity']
                
                if cvss_score >= min_score:
                    description = "No description available"
                    if cve_data['descriptions']:
                        description = cve_data['descriptions'][0]['value']
                    
                    # Extract affected products
                    products = []
                    if 'configurations' in cve_data:
                        for config in cve_data['configurations']:
                            for node in config.get('nodes', []):
                                for cpe_match in node.get('cpeMatch', []):
                                    cpe = cpe_match['criteria']
                                    product = cpe.split(':')[3:5]
                                    if product not in products:
                                        products.extend(product)
                    
                    cve_info = {
                        'CVE-ID': cve_data['id'],
                        'Score': cvss_score,
                        'Severity': severity,
                        'Published': cve_data['published'][:10],
                        'Vector': vector,
                        'Products': ', '.join(products[:3]),
                        'Description': description[:80] + "..." if len(description) > 80 else description
                    }
                    
                    high_risk_cves.append(cve_info)
                    
                    # Cache to database
                    self.db.cache_cve({
                        'id': cve_data['id'],
                        'score': cvss_score,
                        'published': cve_data['published'],
                        'description': description,
                        'references': [ref['url'] for ref in cve_data.get('references', [])],
                        'tags': products
                    })
            
            return sorted(high_risk_cves, key=lambda x: x['Score'], reverse=True)
            
        except requests.RequestException as e:
            print(f"{Colors.RED}[!] Error fetching CVEs: {e}{Colors.RESET}")
            return []
    
    def hunt_github_pocs(self, cve_id):
        """Hunt for GitHub Proof-of-Concepts"""
        print(f"{Colors.YELLOW}[*] 🔍 Hunting GitHub PoCs for {cve_id}...{Colors.RESET}")
        
        headers = {'Accept': 'application/vnd.github.v3+json'}
        if self.config.get('github_token'):
            headers['Authorization'] = f"token {self.config['github_token']}"
        
        search_queries = [
            f"{cve_id} exploit",
            f"{cve_id} poc",
            f"{cve_id} vulnerability"
        ]
        
        pocs = []
        for query in search_queries:
            try:
                url = f"https://api.github.com/search/repositories"
                params = {
                    'q': query,
                    'sort': 'stars',
                    'order': 'desc',
                    'per_page': 10
                }
                
                response = requests.get(url, headers=headers, params=params, timeout=15)
                if response.status_code == 200:
                    data = response.json()
                    
                    for repo in data.get('items', []):
                        poc_info = {
                            'Repository': repo['full_name'],
                            'Stars': repo['stargazers_count'],
                            'Description': repo['description'][:60] + "..." if repo['description'] else "No description",
                            'URL': repo['html_url'],
                            'Language': repo['language'] or 'Unknown'
                        }
                        pocs.append(poc_info)
                
                time.sleep(1)  # Rate limiting
                
            except Exception as e:
                print(f"{Colors.RED}[!] Error searching GitHub: {e}{Colors.RESET}")
        
        return pocs[:5]  # Return top 5 PoCs
    
    def advanced_subdomain_enum(self, domain, wordlist_size="medium"):
        """Advanced subdomain enumeration"""
        print(f"{Colors.YELLOW}[*] 🌐 Advanced Subdomain Discovery for {domain}...{Colors.RESET}")
        
        subdomains = set()
        
        # DNS enumeration
        common_subs = self.config['wordlists']['subdomains']
        if wordlist_size == "large":
            common_subs.extend(['mail', 'ftp', 'cpanel', 'webmail', 'smtp', 'pop', 'ns1', 'ns2', 
                               'mx', 'email', 'cloud', 'portal', 'secure', 'vpn', 'remote'])
        
        def check_subdomain(sub):
            full_domain = f"{sub}.{domain}"
            try:
                socket.gethostbyname(full_domain)
                return full_domain
            except:
                return None
        
        with ThreadPoolExecutor(max_workers=50) as executor:
            results = executor.map(check_subdomain, common_subs)
            subdomains.update(filter(None, results))
        
        # Certificate transparency logs
        try:
            ct_url = f"https://crt.sh/?q=%.{domain}&output=json"
            response = requests.get(ct_url, timeout=10)
            if response.status_code == 200:
                ct_data = response.json()
                for entry in ct_data:
                    name = entry.get('name_value', '')
                    if name and not name.startswith('*'):
                        subdomains.add(name.lower())
        except:
            pass
        
        return list(subdomains)[:20]  # Return top 20
    
    def technology_detection(self, domain):
        """Detect technologies used by target"""
        print(f"{Colors.YELLOW}[*] 🔧 Technology Stack Detection for {domain}...{Colors.RESET}")
        
        try:
            url = f"https://{domain}"
            response = self.session.get(url, timeout=10, allow_redirects=True)
            
            technologies = {}
            headers = response.headers
            content = response.text.lower()
            
            # Server detection
            if 'server' in headers:
                technologies['Web Server'] = headers['server']
            
            # Framework detection
            frameworks = {
                'WordPress': ['wp-content', 'wp-includes'],
                'Drupal': ['drupal', '/sites/default'],
                'Joomla': ['joomla', '/administrator'],
                'Django': ['django', 'csrftoken'],
                'Laravel': ['laravel', '_token'],
                'React': ['react', '__react'],
                'Angular': ['angular', 'ng-version'],
                'Vue.js': ['vue', '__vue__']
            }
            
            for framework, indicators in frameworks.items():
                if any(indicator in content for indicator in indicators):
                    technologies['Framework'] = framework
                    break
            
            # Language detection
            languages = {
                'PHP': ['.php', 'phpsessionid'],
                'ASP.NET': ['asp.net', '__viewstate'],
                'Java': ['jsessionid', '.jsp'],
                'Python': ['django', 'flask'],
                'Ruby': ['ruby', 'rails'],
                'Node.js': ['express', 'node']
            }
            
            for lang, indicators in languages.items():
                if any(indicator in content for indicator in indicators):
                    technologies['Language'] = lang
                    break
            
            # CDN detection
            cdns = {
                'Cloudflare': ['cloudflare', 'cf-ray'],
                'AWS CloudFront': ['cloudfront', 'amazon'],
                'Fastly': ['fastly', 'fastly-ssl'],
                'MaxCDN': ['maxcdn', 'bootstrapcdn']
            }
            
            for cdn, indicators in cdns.items():
                if any(indicator in str(headers).lower() for indicator in indicators):
                    technologies['CDN'] = cdn
                    break
            
            return technologies
            
        except Exception as e:
            print(f"{Colors.RED}[!] Technology detection failed: {e}{Colors.RESET}")
            return {}
    
    def advanced_port_scanner(self, domain, ports=None):
        """Advanced port scanning with banner grabbing"""
        print(f"{Colors.YELLOW}[*] 🚪 Advanced Port Scanning {domain}...{Colors.RESET}")
        
        if ports is None:
            ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3389, 5432, 3306, 1433, 6379, 27017]
        
        try:
            target_ip = socket.gethostbyname(domain)
        except:
            print(f"{Colors.RED}[!] Cannot resolve {domain}{Colors.RESET}")
            return []
        
        open_ports = []
        
        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                result = sock.connect_ex((target_ip, port))
                
                if result == 0:
                    # Banner grabbing
                    banner = ""
                    try:
                        sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
                        banner = sock.recv(1024).decode().strip()
                    except:
                        pass
                    
                    service = self.get_service_name(port)
                    return {
                        'Port': port,
                        'Service': service,
                        'Banner': banner[:50] + "..." if len(banner) > 50 else banner
                    }
                sock.close()
            except:
                pass
            return None
        
        with ThreadPoolExecutor(max_workers=100) as executor:
            results = executor.map(scan_port, ports)
            open_ports = [port for port in results if port is not None]
        
        return open_ports
    
    def get_service_name(self, port):
        services = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
            53: 'DNS', 80: 'HTTP', 110: 'POP3', 143: 'IMAP',
            443: 'HTTPS', 993: 'IMAPS', 995: 'POP3S',
            3389: 'RDP', 5432: 'PostgreSQL', 3306: 'MySQL',
            1433: 'MSSQL', 6379: 'Redis', 27017: 'MongoDB'
        }
        return services.get(port, 'Unknown')
    
    def shodan_intelligence(self, domain):
        """Gather intelligence using Shodan"""
        if not self.shodan_api:
            return {"error": "Shodan API key not configured"}
        
        print(f"{Colors.YELLOW}[*] 🌍 Shodan Intelligence Gathering for {domain}...{Colors.RESET}")
        
        try:
            # Resolve domain to IP
            ip = socket.gethostbyname(domain)
            
            # Get host information
            host_info = self.shodan_api.host(ip)
            
            shodan_data = {
                'IP': ip,
                'Organization': host_info.get('org', 'Unknown'),
                'OS': host_info.get('os', 'Unknown'),
                'Country': host_info.get('country_name', 'Unknown'),
                'City': host_info.get('city', 'Unknown'),
                'ISP': host_info.get('isp', 'Unknown'),
                'Open Ports': host_info.get('ports', []),
                'Vulnerabilities': len(host_info.get('vulns', [])),
                'Last Updated': host_info.get('last_update', 'Unknown')
            }
            
            return shodan_data
            
        except Exception as e:
            return {"error": f"Shodan lookup failed: {e}"}
    
    def vulnerability_timeline(self, cve_list):
        """Create vulnerability timeline analysis"""
        print(f"{Colors.YELLOW}[*] 📊 Creating Vulnerability Timeline...{Colors.RESET}")
        
        timeline = {}
        for cve in cve_list:
            year = cve.get('Published', '2024')[:4]
            if year not in timeline:
                timeline[year] = {'count': 0, 'avg_score': 0, 'cves': []}
            
            timeline[year]['count'] += 1
            timeline[year]['cves'].append(cve)
        
        # Calculate average scores
        for year in timeline:
            scores = [cve.get('Score', 0) for cve in timeline[year]['cves']]
            timeline[year]['avg_score'] = sum(scores) / len(scores) if scores else 0
        
        return timeline
    
    def generate_comprehensive_report(self, data, report_type):
        """Generate comprehensive HTML report"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>CVE Hunter X Report - {report_type}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ background: #2c3e50; color: white; padding: 20px; border-radius: 8px; }}
                .section {{ margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 8px; }}
                .critical {{ background-color: #f8d7da; border-color: #f5c6cb; }}
                .high {{ background-color: #fff3cd; border-color: #ffeaa7; }}
                .medium {{ background-color: #d1ecf1; border-color: #bee5eb; }}
                table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🔥 CVE Hunter X Report</h1>
                <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                <p>Report Type: {report_type.title()}</p>
            </div>
        """
        
        # Add data sections based on type
        if report_type == "comprehensive":
            html_content += f"""
            <div class="section critical">
                <h2>🚨 Critical Findings Summary</h2>
                <p>Total CVEs Analyzed: {len(data.get('cves', []))}</p>
                <p>High Risk CVEs: {len([c for c in data.get('cves', []) if c.get('Score', 0) >= 8.0])}</p>
                <p>PoCs Available: {len(data.get('pocs', []))}</p>
            </div>
            """
        
        html_content += """
        </body>
        </html>
        """
        
        filename = f"Hunter_report_{report_type}_{timestamp}.html"
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        # Also create JSON backup
        json_filename = f"Hunter_data_{report_type}_{timestamp}.json"
        with open(json_filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, default=str)
        
        print(f"{Colors.GREEN}[+] 📄 Comprehensive report saved:")
        print(f"    • HTML: {filename}")
        print(f"    • JSON: {json_filename}{Colors.RESET}")
        
        return filename, json_filename

def main():
    parser = argparse.ArgumentParser(description='CVE Hunter X - Advanced Bug Bounty Research Platform')
    parser.add_argument('--recent', type=int, help='Get recent high-risk CVEs (days)', metavar='DAYS')
    parser.add_argument('--score', type=float, default=7.0, help='Minimum CVSS score filter')
    parser.add_argument('--search', type=str, help='Search CVEs by keyword', metavar='KEYWORD')
    parser.add_argument('--details', type=str, help='Get CVE details with PoC hunt', metavar='CVE-ID')
    parser.add_argument('--recon', type=str, help='Full reconnaissance on domain', metavar='DOMAIN')
    parser.add_argument('--subdomains', type=str, help='Subdomain enumeration', metavar='DOMAIN')
    parser.add_argument('--portscan', type=str, help='Advanced port scanning', metavar='DOMAIN')
    parser.add_argument('--tech', type=str, help='Technology detection', metavar='DOMAIN')
    parser.add_argument('--shodan', type=str, help='Shodan intelligence', metavar='DOMAIN')
    parser.add_argument('--report', action='store_true', help='Generate comprehensive HTML report')
    parser.add_argument('--wordlist', choices=['small', 'medium', 'large'], default='medium', help='Wordlist size')
    
    args = parser.parse_args()
    
    hunter = CVEHunterX()
    hunter.display_banner()
    
    if args.recent:
        print(f"{Colors.CYAN}[*] 🚀 Initiating Advanced CVE Discovery...{Colors.RESET}")
        cves = hunter.get_recent_cves_advanced(days=args.recent, min_score=args.score)
        
        if cves:
            print(f"\n{Colors.GREEN}[+] 🎯 High-Risk CVEs Discovered: {len(cves)}{Colors.RESET}")
            print(tabulate(cves, headers="keys", tablefmt="fancy_grid"))
            
            # Timeline analysis
            timeline = hunter.vulnerability_timeline(cves)
            print(f"\n{Colors.CYAN}📊 Vulnerability Timeline Analysis:{Colors.RESET}")
            for year, stats in timeline.items():
                print(f"  {year}: {stats['count']} CVEs (Avg Score: {stats['avg_score']:.1f})")
            
            if args.report:
                hunter.generate_comprehensive_report({
                    'cves': cves,
                    'timeline': timeline,
                    'summary': {'total': len(cves), 'critical': len([c for c in cves if c.get('Score', 0) >= 9.0])}
                }, "recent_cves")
    
    elif args.details:
        print(f"{Colors.CYAN}[*] 🔍 Deep Dive Analysis for {args.details}...{Colors.RESET}")
        
        # Get CVE details (using existing method)
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0"
        params = {'cveId': args.details}
        
        try:
            response = hunter.session.get(url, params=params, timeout=30)
            data = response.json()
            
            if data.get('vulnerabilities'):
                cve = data['vulnerabilities'][0]['cve']
                print(f"\n{Colors.GREEN}[+] CVE Information:{Colors.RESET}")
                print(f"ID: {cve['id']}")
                print(f"Published: {cve.get('published', 'N/A')}")
                print(f"Description: {cve['descriptions'][0]['value'] if cve['descriptions'] else 'N/A'}")
                
                # Hunt for PoCs
                pocs = hunter.hunt_github_pocs(args.details)
                if pocs:
                    print(f"\n{Colors.YELLOW}[+] 🔥 GitHub PoCs Found: {len(pocs)}{Colors.RESET}")
                    print(tabulate(pocs, headers="keys", tablefmt="fancy_grid"))
                    
                    if args.report:
                        hunter.generate_comprehensive_report({
                            'cve': cve,
                            'pocs': pocs
                        }, "cve_analysis")
        except Exception as e:
            print(f"{Colors.RED}[!] Error: {e}{Colors.RESET}")
    
    elif args.recon:
        print(f"{Colors.CYAN}[*] 🎯 Full Hunter Reconnaissance on {args.recon}...{Colors.RESET}")
        
        recon_data = {}
        
        # Subdomain enumeration
        subdomains = hunter.advanced_subdomain_enum(args.recon, args.wordlist)
        recon_data['subdomains'] = subdomains
        
        # Technology detection
        tech = hunter.technology_detection(args.recon)
        recon_data['technologies'] = tech
        
        # Port scanning
        ports = hunter.advanced_port_scanner(args.recon)
        recon_data['ports'] = ports
        
        # Shodan intelligence
        shodan_data = hunter.shodan_intelligence(args.recon)
        recon_data['shodan'] = shodan_data
        
        # Display results
        print(f"\n{Colors.GREEN}[+] 🌐 Subdomains ({len(subdomains)}):{Colors.RESET}")
        for sub in subdomains[:10]:  # Show first 10
            print(f"  • {sub}")
        
        print(f"\n{Colors.GREEN}[+] 🔧 Technologies:{Colors.RESET}")
        for tech_type, tech_name in tech.items():
            print(f"  • {tech_type}: {tech_name}")
        
        if ports:
            print(f"\n{Colors.GREEN}[+] 🚪 Open Ports ({len(ports)}):{Colors.RESET}")
            print(tabulate(ports, headers="keys", tablefmt="fancy_grid"))
        
        if 'error' not in shodan_data:
            print(f"\n{Colors.GREEN}[+] 🌍 Shodan Intelligence:{Colors.RESET}")
            for key, value in shodan_data.items():
                print(f"  • {key}: {value}")
        
        if args.report:
            hunter.generate_comprehensive_report(recon_data, "full_recon")
    
    else:
        # Interactive mode dengan menu yang lebih keren
        while True:
            print(f"""
{Colors.CYAN}╔═══════════════════════════════════════════════════════════════╗
║                    CVE Hunter X - Main Menu                   ║
╠═══════════════════════════════════════════════════════════════╣
║  1. 🚀 Advanced CVE Discovery     6. 🔧 Technology Detection  ║
║  2. 🔍 CVE Deep Analysis + PoCs   7. 🌍 Shodan Intelligence   ║
║  3. 🎯 Full Domain Reconnaissance 8. 📊 Vulnerability Stats   ║
║  4. 🌐 Subdomain Enumeration      9. ⚙️  Configuration         ║
║  5. 🚪 Advanced Port Scanner      0. 🚪 Exit Hunter X         ║
╚═══════════════════════════════════════════════════════════════╝{Colors.RESET}
            """)
            
            choice = input(f"{Colors.WHITE}🎯 Select your weapon [0-9]: {Colors.RESET}")
            
            if choice == '1':
                days = input(f"{Colors.WHITE}📅 Days to scan (default 7): {Colors.RESET}") or "7"
                min_score = input(f"{Colors.WHITE}⚡ Minimum CVSS score (default 7.0): {Colors.RESET}") or "7.0"
                keywords = input(f"{Colors.WHITE}🔍 Keywords (optional): {Colors.RESET}") or None
                
                cves = hunter.get_recent_cves_advanced(days=int(days), min_score=float(min_score), keywords=keywords)
                
                if cves:
                    print(f"\n{Colors.GREEN}[+] 🎯 High-Risk CVEs Discovered: {len(cves)}{Colors.RESET}")
                    print(tabulate(cves, headers="keys", tablefmt="fancy_grid"))
                    
                    timeline = hunter.vulnerability_timeline(cves)
                    print(f"\n{Colors.CYAN}📊 Vulnerability Timeline:{Colors.RESET}")
                    for year, stats in timeline.items():
                        print(f"  {year}: {stats['count']} CVEs (Avg Score: {stats['avg_score']:.1f})")
                    
                    generate_report = input(f"\n{Colors.YELLOW}📄 Generate HTML report? (y/n): {Colors.RESET}").lower() == 'y'
                    if generate_report:
                        hunter.generate_comprehensive_report({
                            'cves': cves,
                            'timeline': timeline
                        }, "advanced_discovery")
            
            elif choice == '2':
                cve_id = input(f"{Colors.WHITE}🎯 Enter CVE ID (e.g., CVE-2023-12345): {Colors.RESET}")
                if cve_id:
                    print(f"{Colors.CYAN}[*] 🔍 Deep diving into {cve_id}...{Colors.RESET}")
                    
                    # Get CVE details
                    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0"
                    params = {'cveId': cve_id}
                    
                    try:
                        response = hunter.session.get(url, params=params, timeout=30)
                        data = response.json()
                        
                        if data.get('vulnerabilities'):
                            cve = data['vulnerabilities'][0]['cve']
                            
                            # Display CVE info
                            print(f"\n{Colors.GREEN}[+] 🎯 CVE Information:{Colors.RESET}")
                            print(f"  • ID: {cve['id']}")
                            print(f"  • Published: {cve.get('published', 'N/A')}")
                            print(f"  • Modified: {cve.get('lastModified', 'N/A')}")
                            
                            if cve['descriptions']:
                                desc = cve['descriptions'][0]['value']
                                print(f"  • Description: {desc[:200]}{'...' if len(desc) > 200 else ''}")
                            
                            # CVSS Info
                            if 'metrics' in cve:
                                if 'cvssMetricV31' in cve['metrics']:
                                    cvss = cve['metrics']['cvssMetricV31'][0]['cvssData']
                                    print(f"  • CVSS Score: {cvss['baseScore']} ({cvss['baseSeverity']})")
                                    print(f"  • Vector: {cvss['vectorString']}")
                            
                            # References
                            if cve.get('references'):
                                print(f"  • References: {len(cve['references'])} links")
                                for i, ref in enumerate(cve['references'][:3]):
                                    print(f"    [{i+1}] {ref['url']}")
                            
                            # Hunt GitHub PoCs
                            pocs = hunter.hunt_github_pocs(cve_id)
                            if pocs:
                                print(f"\n{Colors.YELLOW}[+] 🔥 GitHub PoCs Found: {len(pocs)}{Colors.RESET}")
                                print(tabulate(pocs, headers="keys", tablefmt="fancy_grid"))
                            else:
                                print(f"{Colors.RED}[!] No GitHub PoCs found for {cve_id}{Colors.RESET}")
                            
                            # Generate report option
                            generate_report = input(f"\n{Colors.YELLOW}📄 Generate detailed report? (y/n): {Colors.RESET}").lower() == 'y'
                            if generate_report:
                                hunter.generate_comprehensive_report({
                                    'cve': cve,
                                    'pocs': pocs
                                }, "cve_deep_analysis")
                        else:
                            print(f"{Colors.RED}[!] CVE {cve_id} not found{Colors.RESET}")
                    
                    except Exception as e:
                        print(f"{Colors.RED}[!] Error fetching CVE: {e}{Colors.RESET}")
            
            elif choice == '3':
                domain = input(f"{Colors.WHITE}🎯 Target domain (without https://): {Colors.RESET}")
                if domain:
                    print(f"{Colors.CYAN}[*] 🎯 Full Hunter Reconnaissance on {domain}...{Colors.RESET}")
                    
                    recon_data = {}
                    
                    # Multi-threaded reconnaissance
                    print(f"{Colors.YELLOW}[*] Phase 1: Subdomain Discovery...{Colors.RESET}")
                    subdomains = hunter.advanced_subdomain_enum(domain, "large")
                    recon_data['subdomains'] = subdomains
                    
                    print(f"{Colors.YELLOW}[*] Phase 2: Technology Stack Detection...{Colors.RESET}")
                    tech = hunter.technology_detection(domain)
                    recon_data['technologies'] = tech
                    
                    print(f"{Colors.YELLOW}[*] Phase 3: Port Scanning & Banner Grabbing...{Colors.RESET}")
                    ports = hunter.advanced_port_scanner(domain)
                    recon_data['ports'] = ports
                    
                    print(f"{Colors.YELLOW}[*] Phase 4: Shodan Intelligence Gathering...{Colors.RESET}")
                    shodan_data = hunter.shodan_intelligence(domain)
                    recon_data['shodan'] = shodan_data
                    
                    # Display comprehensive results
                    print(f"\n{Colors.GREEN}╔═══ 🎯 RECONNAISSANCE RESULTS ═══╗{Colors.RESET}")
                    
                    print(f"\n{Colors.GREEN}[+] 🌐 Subdomains Discovered ({len(subdomains)}):{Colors.RESET}")
                    for i, sub in enumerate(subdomains[:15], 1):
                        print(f"  {i:2d}. {sub}")
                    if len(subdomains) > 15:
                        print(f"     ... and {len(subdomains)-15} more")
                    
                    print(f"\n{Colors.GREEN}[+] 🔧 Technology Stack:{Colors.RESET}")
                    if tech:
                        for tech_type, tech_name in tech.items():
                            print(f"  • {tech_type}: {Colors.CYAN}{tech_name}{Colors.RESET}")
                    else:
                        print(f"  {Colors.YELLOW}[!] Unable to detect technologies{Colors.RESET}")
                    
                    if ports:
                        print(f"\n{Colors.GREEN}[+] 🚪 Open Ports & Services ({len(ports)}):{Colors.RESET}")
                        print(tabulate(ports, headers="keys", tablefmt="fancy_grid"))
                    
                    if 'error' not in shodan_data:
                        print(f"\n{Colors.GREEN}[+] 🌍 Shodan Intelligence:{Colors.RESET}")
                        for key, value in shodan_data.items():
                            if key != 'error':
                                print(f"  • {key}: {Colors.CYAN}{value}{Colors.RESET}")
                    else:
                        print(f"\n{Colors.YELLOW}[!] Shodan: {shodan_data['error']}{Colors.RESET}")
                    
                    print(f"\n{Colors.GREEN}╚═══════════════════════════════════╝{Colors.RESET}")
                    
                    # Generate comprehensive report
                    generate_report = input(f"\n{Colors.YELLOW}📄 Generate comprehensive HTML report? (y/n): {Colors.RESET}").lower() == 'y'
                    if generate_report:
                        hunter.generate_comprehensive_report(recon_data, "full_reconnaissance")
            
            elif choice == '4':
                domain = input(f"{Colors.WHITE}🌐 Domain for subdomain enum: {Colors.RESET}")
                wordlist_size = input(f"{Colors.WHITE}📝 Wordlist size (small/medium/large) [medium]: {Colors.RESET}") or "medium"
                
                if domain:
                    subdomains = hunter.advanced_subdomain_enum(domain, wordlist_size)
                    
                    print(f"\n{Colors.GREEN}[+] 🌐 Subdomains Found ({len(subdomains)}):{Colors.RESET}")
                    for i, sub in enumerate(subdomains, 1):
                        print(f"  {i:2d}. {sub}")
                    
                    if not subdomains:
                        print(f"{Colors.YELLOW}[!] No subdomains discovered{Colors.RESET}")
            
            elif choice == '5':
                domain = input(f"{Colors.WHITE}🚪 Target for port scanning: {Colors.RESET}")
                custom_ports = input(f"{Colors.WHITE}🔢 Custom ports (comma-separated) or Enter for default: {Colors.RESET}")
                
                if domain:
                    ports_to_scan = None
                    if custom_ports:
                        try:
                            ports_to_scan = [int(p.strip()) for p in custom_ports.split(',')]
                        except:
                            print(f"{Colors.RED}[!] Invalid port format, using defaults{Colors.RESET}")
                    
                    ports = hunter.advanced_port_scanner(domain, ports_to_scan)
                    
                    if ports:
                        print(f"\n{Colors.GREEN}[+] 🚪 Open Ports & Services:{Colors.RESET}")
                        print(tabulate(ports, headers="keys", tablefmt="fancy_grid"))
                    else:
                        print(f"{Colors.YELLOW}[!] No open ports detected or host unreachable{Colors.RESET}")
            
            elif choice == '6':
                domain = input(f"{Colors.WHITE}🔧 Domain for tech detection: {Colors.RESET}")
                
                if domain:
                    tech = hunter.technology_detection(domain)
                    
                    print(f"\n{Colors.GREEN}[+] 🔧 Technology Stack Detected:{Colors.RESET}")
                    if tech:
                        for tech_type, tech_name in tech.items():
                            print(f"  • {tech_type}: {Colors.CYAN}{tech_name}{Colors.RESET}")
                    else:
                        print(f"{Colors.YELLOW}[!] Unable to detect technologies{Colors.RESET}")
            
            elif choice == '7':
                domain = input(f"{Colors.WHITE}🌍 Domain for Shodan lookup: {Colors.RESET}")
                
                if domain:
                    shodan_data = hunter.shodan_intelligence(domain)
                    
                    print(f"\n{Colors.GREEN}[+] 🌍 Shodan Intelligence:{Colors.RESET}")
                    if 'error' not in shodan_data:
                        for key, value in shodan_data.items():
                            print(f"  • {key}: {Colors.CYAN}{value}{Colors.RESET}")
                    else:
                        print(f"{Colors.RED}[!] {shodan_data['error']}{Colors.RESET}")
            
            elif choice == '8':
                print(f"\n{Colors.CYAN}📊 CVE Hunter X Statistics:{Colors.RESET}")
                
                # Database stats
                conn = sqlite3.connect(cve.db.db_path)
                cursor = conn.cursor()
                
                cursor.execute("SELECT COUNT(*) FROM cves")
                cached_cves = cursor.fetchone()[0]
                
                cursor.execute("SELECT COUNT(*) FROM targets")
                scanned_targets = cursor.fetchone()[0]
                
                cursor.execute("SELECT AVG(score) FROM cves WHERE score > 0")
                avg_score = cursor.fetchone()[0] or 0
                
                conn.close()
                
                print(f"  • Cached CVEs: {Colors.GREEN}{cached_cves}{Colors.RESET}")
                print(f"  • Scanned Targets: {Colors.GREEN}{scanned_targets}{Colors.RESET}")
                print(f"  • Average CVE Score: {Colors.GREEN}{avg_score:.1f}{Colors.RESET}")
                print(f"  • Database Size: {Colors.GREEN}{os.path.getsize(cve.db.db_path)/1024:.1f} KB{Colors.RESET}")
            
            elif choice == '9':
                print(f"\n{Colors.CYAN}⚙️  Configuration Management:{Colors.RESET}")
                print("1. View current config")
                print("2. Set Shodan API key")
                print("3. Set GitHub token")
                print("4. Reset configuration")
                
                config_choice = input(f"{Colors.WHITE}Select option: {Colors.RESET}")
                
                if config_choice == '1':
                    print(f"\n{Colors.GREEN}Current Configuration:{Colors.RESET}")
                    for key, value in hunter.config.items():
                        if 'key' in key.lower() or 'token' in key.lower():
                            masked_value = f"{'*' * (len(str(value))-4)}{str(value)[-4:]}" if value else "Not set"
                            print(f"  • {key}: {masked_value}")
                        else:
                            print(f"  • {key}: {value}")
                
                elif config_choice == '2':
                    api_key = input(f"{Colors.WHITE}Enter Shodan API key: {Colors.RESET}")
                    hunter.config['shodan_api_key'] = api_key
                    with open('config.yaml', 'w') as f:
                        yaml.dump(hunter.config, f)
                    print(f"{Colors.GREEN}[+] Shodan API key updated{Colors.RESET}")
                
                elif config_choice == '3':
                    token = input(f"{Colors.WHITE}Enter GitHub token: {Colors.RESET}")
                    hunter.config['github_token'] = token
                    with open('config.yaml', 'w') as f:
                        yaml.dump(hunter.config, f)
                    print(f"{Colors.GREEN}[+] GitHub token updated{Colors.RESET}")
            
            elif choice == '0':
                print(f"""
{Colors.GREEN}╔═══════════════════════════════════════════════════════════════╗
║                     Thanks for using CVE Hunter X!            ║
║                                                               ║
║  🎯 Happy Bug Hunting, Bosku!                                 ║
║  🔥 Stay ethical, stay powerful!                              ║
║                                                               ║
║  💡 Remember: With great power comes great responsibility     ║
╚═══════════════════════════════════════════════════════════════╝{Colors.RESET}
                """)
                break
            
            else:
                print(f"{Colors.RED}[!] Invalid choice. Please select 0-9{Colors.RESET}")
            
            input(f"\n{Colors.YELLOW}Press Enter to continue...{Colors.RESET}")

if __name__ == "__main__":
    try:
        os.system('clear')
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[*] CVE Hunter X shutting down... Happy hunting, bosku!{Colors.RESET}")
        sys.exit(0)
    except Exception as e:
        print(f"{Colors.RED}[!] Critical error: {e}{Colors.RESET}")
        sys.exit(1)
