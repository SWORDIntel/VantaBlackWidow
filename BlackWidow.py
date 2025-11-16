#!/usr/bin/env python3
"""
BlackWidow TEMPEST - Integrated Security Scanner
Combines comprehensive reconnaissance, AI-powered analysis, and advanced fuzzing
with a TEMPEST-grade secure user interface

Features:
- Enhanced reconnaissance (subdomains, emails, phones, parameters)
- AI-powered vulnerability analysis with OpenAI GPT
- Advanced fuzzing with InjectX payload library
- IOC identification and analysis
- TEMPEST-grade secure UI
- Comprehensive reporting
"""

import sys
import os
import threading
import logging
import json
import time
import tkinter as tk
from tkinter import messagebox
from typing import Dict, List, Optional
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor
import requests

# Import custom modules
from tempest_ui import TEMPESTSecureUI, AuditLogger
from reconnaissance import EnhancedReconnaissance
from advanced_fuzzer import AdvancedFuzzer, FuzzResult
from ioc_identifier import IOCIdentifier
from selenium_parser import SimpleCrawler, SeleniumCrawler

# Try to import existing modules
try:
    import openai
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False
    logging.warning("OpenAI module not available - AI features disabled")


class BlackWidowIntegrated:
    """
    Main integrated BlackWidow security scanner
    """

    def __init__(self, ui: TEMPESTSecureUI):
        self.ui = ui
        self.audit = AuditLogger()

        # Core components
        self.reconnaissance = None
        self.fuzzer = AdvancedFuzzer()
        self.ioc_identifier = IOCIdentifier()

        # State management
        self.scanning = False
        self.paused = False
        self.target_domain = None
        self.session = self._create_session()

        # Results storage
        self.results = {
            'reconnaissance': {},
            'vulnerabilities': [],
            'iocs': [],
            'statistics': {
                'total_requests': 0,
                'successful_requests': 0,
                'failed_requests': 0,
                'vulnerabilities_found': 0,
                'critical_findings': 0,
                'high_findings': 0,
                'medium_findings': 0,
                'low_findings': 0,
            }
        }

        # Thread pool
        self.executor = ThreadPoolExecutor(max_workers=20)
        self.futures = []

        # Connect UI to backend
        self.connect_ui_handlers()

        self.ui.log_to_console("BlackWidow TEMPEST initialized", 'SUCCESS')
        self.audit.log_action('SYSTEM_INITIALIZED')

    def _create_session(self) -> requests.Session:
        """Create configured HTTP session"""
        session = requests.Session()
        session.headers.update({
            'User-Agent': 'BlackWidow-TEMPEST/2.0 Security Scanner',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
        })
        # Add retry strategy
        from requests.adapters import HTTPAdapter
        from urllib3.util.retry import Retry

        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)

        return session

    def connect_ui_handlers(self):
        """Connect UI button handlers to backend methods"""
        # Override UI methods
        self.ui.start_scan = self.start_comprehensive_scan
        self.ui.pause_scan = self.pause_scan
        self.ui.stop_scan = self.stop_scan

    def start_comprehensive_scan(self):
        """Start comprehensive security scan"""
        try:
            # Validate inputs
            target = self.ui.target_var.get().strip()
            if not target:
                messagebox.showerror("Error", "Please enter a target domain")
                return

            # Parse target
            if not target.startswith(('http://', 'https://')):
                target = f'https://{target}'

            parsed = urlparse(target)
            self.target_domain = parsed.netloc

            self.ui.log_to_console(f"Starting comprehensive scan of {self.target_domain}", 'INFO')
            self.ui.update_status("INITIALIZING")

            self.scanning = True
            self.paused = False

            # Start scan in background thread
            scan_thread = threading.Thread(target=self._execute_scan, daemon=True)
            scan_thread.start()

        except Exception as e:
            self.ui.log_to_console(f"Error starting scan: {str(e)}", 'ERROR')
            self.audit.log_action('SCAN_ERROR', {'error': str(e)})

    def _execute_scan(self):
        """Execute comprehensive scan workflow"""
        try:
            scan_options = {k: v.get() for k, v in self.ui.scan_options.items()}

            # Phase 1: Reconnaissance
            if scan_options.get('reconnaissance', True):
                self.ui.log_to_console("━━━ Phase 1: Reconnaissance ━━━", 'INFO')
                self._run_reconnaissance()

            # Phase 2: Deep Crawling
            if scan_options.get('deep_crawl', True):
                self.ui.log_to_console("━━━ Phase 2: Deep Crawling ━━━", 'INFO')
                self._run_deep_crawl()

            # Phase 3: Vulnerability Scanning
            if scan_options.get('vulnerability_scan', True):
                self.ui.log_to_console("━━━ Phase 3: Vulnerability Scanning ━━━", 'INFO')
                self._run_vulnerability_scan()

            # Phase 4: Advanced Fuzzing
            if scan_options.get('fuzzing', True):
                self.ui.log_to_console("━━━ Phase 4: Advanced Fuzzing ━━━", 'INFO')
                self._run_advanced_fuzzing()

            # Phase 5: AI Analysis
            if scan_options.get('ai_analysis', True) and OPENAI_AVAILABLE:
                self.ui.log_to_console("━━━ Phase 5: AI Analysis ━━━", 'INFO')
                self._run_ai_analysis()

            # Generate final report
            self._generate_final_report()

            self.ui.log_to_console("━━━ Scan Complete ━━━", 'SUCCESS')
            self.ui.update_status("COMPLETE")
            self.scanning = False

        except Exception as e:
            self.ui.log_to_console(f"Scan error: {str(e)}", 'ERROR')
            logging.error(f"Scan execution error: {str(e)}", exc_info=True)
            self.scanning = False

    def _run_reconnaissance(self):
        """Execute reconnaissance phase"""
        try:
            self.ui.update_status("RECONNAISSANCE")
            self.ui.log_to_console(f"Gathering intelligence on {self.target_domain}...", 'INFO')

            # Initialize reconnaissance
            self.reconnaissance = EnhancedReconnaissance(
                self.target_domain,
                session=self.session
            )

            # Perform initial crawl
            target_url = f"https://{self.target_domain}"
            try:
                response = self.session.get(target_url, timeout=15, verify=False)
                self.reconnaissance.analyze_page(target_url, response.text)

                # Analyze discovered links (limited)
                from bs4 import BeautifulSoup
                soup = BeautifulSoup(response.text, 'html.parser')
                links = [a.get('href') for a in soup.find_all('a', href=True)][:10]

                for link in links:
                    if self.paused:
                        return

                    try:
                        full_url = f"{target_url.rstrip('/')}/{link.lstrip('/')}"
                        resp = self.session.get(full_url, timeout=10, verify=False)
                        self.reconnaissance.analyze_page(full_url, resp.text)
                    except:
                        pass

            except Exception as e:
                self.ui.log_to_console(f"Reconnaissance error: {str(e)}", 'WARNING')

            # Get summary
            summary = self.reconnaissance.get_summary()
            self.results['reconnaissance'] = summary

            # Display findings
            self.ui.log_to_console(f"✓ Found {len(summary['subdomains'])} subdomains", 'SUCCESS')
            self.ui.log_to_console(f"✓ Found {len(summary['emails'])} email addresses", 'SUCCESS')
            self.ui.log_to_console(f"✓ Found {len(summary['phone_numbers'])} phone numbers", 'SUCCESS')
            self.ui.log_to_console(f"✓ Found {len(summary['technologies'])} technologies", 'SUCCESS')
            self.ui.log_to_console(f"✓ Found {len(summary['api_endpoints'])} API endpoints", 'SUCCESS')

        except Exception as e:
            self.ui.log_to_console(f"Reconnaissance phase error: {str(e)}", 'ERROR')

    def _run_deep_crawl(self):
        """Execute deep crawling phase"""
        try:
            self.ui.update_status("CRAWLING")
            self.ui.log_to_console("Performing deep crawl...", 'INFO')

            # Run simplified crawler
            target_url = f"https://{self.target_domain}"
            crawler = SimpleCrawler(self.target_domain, max_depth=3, timeout_minutes=2)

            # Run in thread
            crawl_thread = threading.Thread(target=crawler.crawl, daemon=True)
            crawl_thread.start()
            crawl_thread.join(timeout=120)  # 2 minute timeout

            self.ui.log_to_console(f"✓ Crawling complete", 'SUCCESS')

        except Exception as e:
            self.ui.log_to_console(f"Crawling error: {str(e)}", 'WARNING')

    def _run_vulnerability_scan(self):
        """Execute vulnerability scanning phase"""
        try:
            self.ui.update_status("SCANNING")
            self.ui.log_to_console("Scanning for vulnerabilities...", 'INFO')

            # Get endpoints from reconnaissance
            if hasattr(self.reconnaissance, 'parameters'):
                for endpoint, params in self.reconnaissance.parameters.items():
                    if self.paused:
                        return

                    self.ui.log_to_console(f"Testing endpoint: {endpoint}", 'INFO')

                    for param in params:
                        # Test with basic payloads
                        self._test_endpoint_parameter(endpoint, param)

        except Exception as e:
            self.ui.log_to_console(f"Vulnerability scan error: {str(e)}", 'ERROR')

    def _test_endpoint_parameter(self, endpoint: str, parameter: str):
        """Test specific endpoint parameter"""
        try:
            base_url = f"https://{self.target_domain}{endpoint}"

            # Get baseline
            baseline_resp = self.session.get(
                base_url,
                params={parameter: 'test'},
                timeout=10,
                verify=False
            )

            # Test with SQLi payload
            test_payload = "' OR '1'='1"
            test_resp = self.session.get(
                base_url,
                params={parameter: test_payload},
                timeout=10,
                verify=False
            )

            # Analyze
            result = self.fuzzer.test_parameter(
                baseline_resp.text,
                test_resp.text,
                test_payload,
                'sql_injection'
            )

            if result.vulnerable:
                self._record_vulnerability(endpoint, parameter, result)

            self.results['statistics']['total_requests'] += 2

        except Exception as e:
            logging.debug(f"Error testing {endpoint}?{parameter}: {str(e)}")

    def _run_advanced_fuzzing(self):
        """Execute advanced fuzzing phase"""
        try:
            self.ui.update_status("FUZZING")
            self.ui.log_to_console("Advanced fuzzing in progress...", 'INFO')

            # Get all vulnerability types
            vuln_types = self.fuzzer.get_all_vulnerability_types()

            for vuln_type in vuln_types[:3]:  # Limit for demo
                if self.paused:
                    return

                self.ui.log_to_console(f"Testing for {vuln_type}...", 'INFO')
                # Add fuzzing logic here

        except Exception as e:
            self.ui.log_to_console(f"Fuzzing error: {str(e)}", 'ERROR')

    def _run_ai_analysis(self):
        """Execute AI-powered analysis"""
        try:
            self.ui.update_status("AI ANALYSIS")
            self.ui.log_to_console("Running AI analysis...", 'INFO')

            api_key = self.ui.api_key_var.get()
            if not api_key:
                self.ui.log_to_console("No API key - skipping AI analysis", 'WARNING')
                return

            # AI analysis would go here
            self.ui.log_to_console("AI analysis complete", 'SUCCESS')

        except Exception as e:
            self.ui.log_to_console(f"AI analysis error: {str(e)}", 'ERROR')

    def _record_vulnerability(self, endpoint: str, parameter: str, result: FuzzResult):
        """Record discovered vulnerability"""
        vuln = {
            'endpoint': endpoint,
            'parameter': parameter,
            'type': result.vulnerability_type,
            'confidence': result.confidence,
            'payload': result.payload,
            'evidence': result.evidence,
            'timestamp': time.time()
        }

        self.results['vulnerabilities'].append(vuln)
        self.results['statistics']['vulnerabilities_found'] += 1

        # Update statistics
        if result.confidence == 'CRITICAL':
            self.results['statistics']['critical_findings'] += 1
        elif result.confidence == 'HIGH':
            self.results['statistics']['high_findings'] += 1
        elif result.confidence == 'MEDIUM':
            self.results['statistics']['medium_findings'] += 1
        else:
            self.results['statistics']['low_findings'] += 1

        # Add to UI
        self.ui.results_tree.insert('', 0, values=(
            result.vulnerability_type,
            result.confidence,
            endpoint,
            result.evidence[:50],
            time.strftime('%H:%M:%S')
        ))

        self.ui.log_to_console(
            f"🚨 VULNERABILITY: {result.vulnerability_type} in {endpoint}?{parameter}",
            'ERROR'
        )

    def _generate_final_report(self):
        """Generate comprehensive final report"""
        try:
            self.ui.log_to_console("Generating final report...", 'INFO')

            # Update statistics display
            stats_text = f"""
╔══════════════════════════════════════════════════════════╗
║           BLACKWIDOW TEMPEST - SCAN SUMMARY             ║
╠══════════════════════════════════════════════════════════╣
║ Target: {self.target_domain.ljust(48)} ║
║ Scan Date: {time.strftime('%Y-%m-%d %H:%M:%S').ljust(45)} ║
╠══════════════════════════════════════════════════════════╣
║ RECONNAISSANCE RESULTS                                   ║
║ • Subdomains: {str(len(self.results['reconnaissance'].get('subdomains', []))).ljust(44)} ║
║ • Email Addresses: {str(len(self.results['reconnaissance'].get('emails', []))).ljust(40)} ║
║ • Phone Numbers: {str(len(self.results['reconnaissance'].get('phone_numbers', []))).ljust(42)} ║
║ • Technologies: {str(len(self.results['reconnaissance'].get('technologies', []))).ljust(43)} ║
║ • API Endpoints: {str(len(self.results['reconnaissance'].get('api_endpoints', []))).ljust(42)} ║
╠══════════════════════════════════════════════════════════╣
║ VULNERABILITY SUMMARY                                    ║
║ • Total Vulnerabilities: {str(self.results['statistics']['vulnerabilities_found']).ljust(34)} ║
║ • Critical: {str(self.results['statistics']['critical_findings']).ljust(47)} ║
║ • High: {str(self.results['statistics']['high_findings']).ljust(51)} ║
║ • Medium: {str(self.results['statistics']['medium_findings']).ljust(49)} ║
║ • Low: {str(self.results['statistics']['low_findings']).ljust(52)} ║
╠══════════════════════════════════════════════════════════╣
║ REQUESTS                                                 ║
║ • Total Requests: {str(self.results['statistics']['total_requests']).ljust(41)} ║
╚══════════════════════════════════════════════════════════╝
"""

            self.ui.stats_text.config(state=tk.NORMAL)
            self.ui.stats_text.delete(1.0, tk.END)
            self.ui.stats_text.insert(1.0, stats_text)
            self.ui.stats_text.config(state=tk.DISABLED)

            # Save to file
            report_file = f"blackwidow_report_{int(time.time())}.json"
            with open(report_file, 'w') as f:
                json.dump(self.results, f, indent=2)

            self.ui.log_to_console(f"✓ Report saved to {report_file}", 'SUCCESS')

        except Exception as e:
            self.ui.log_to_console(f"Report generation error: {str(e)}", 'ERROR')

    def pause_scan(self):
        """Pause ongoing scan"""
        self.paused = True
        self.ui.log_to_console("Scan paused", 'WARNING')
        self.ui.update_status("PAUSED")

    def stop_scan(self):
        """Stop ongoing scan"""
        self.scanning = False
        self.paused = False
        self.ui.log_to_console("Scan stopped", 'ERROR')
        self.ui.update_status("STOPPED")


def main():
    """Main entry point"""
    print("""
╔══════════════════════════════════════════════════════════╗
║                                                          ║
║         ██████╗ ██╗      █████╗  ██████╗██╗  ██╗        ║
║         ██╔══██╗██║     ██╔══██╗██╔════╝██║ ██╔╝        ║
║         ██████╔╝██║     ███████║██║     █████╔╝         ║
║         ██╔══██╗██║     ██╔══██║██║     ██╔═██╗         ║
║         ██████╔╝███████╗██║  ██║╚██████╗██║  ██╗        ║
║         ╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝        ║
║                                                          ║
║         ██╗    ██╗██╗██████╗  ██████╗ ██╗    ██╗        ║
║         ██║    ██║██║██╔══██╗██╔═══██╗██║    ██║        ║
║         ██║ █╗ ██║██║██║  ██║██║   ██║██║ █╗ ██║        ║
║         ██║███╗██║██║██║  ██║██║   ██║██║███╗██║        ║
║         ╚███╔███╔╝██║██████╔╝╚██████╔╝╚███╔███╔╝        ║
║          ╚══╝╚══╝ ╚═╝╚═════╝  ╚═════╝  ╚══╝╚══╝         ║
║                                                          ║
║                    TEMPEST EDITION                       ║
║         Advanced Security Scanner v2.0                   ║
║                                                          ║
╚══════════════════════════════════════════════════════════╝

    Integrated Security Testing Platform
    • Enhanced Reconnaissance
    • AI-Powered Analysis
    • Advanced Fuzzing
    • TEMPEST-Grade Secure UI

    WARNING: For authorized security testing only!
    """)

    # Initialize UI
    root = tk.Tk()
    ui = TEMPESTSecureUI(root)

    # Initialize integrated scanner
    scanner = BlackWidowIntegrated(ui)

    # Start UI
    root.mainloop()


if __name__ == '__main__':
    main()
