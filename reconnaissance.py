"""
Enhanced Reconnaissance Module
Combines comprehensive data gathering with intelligent crawling
"""

import re
import logging
import threading
from urllib.parse import urlparse, urljoin, parse_qs
from collections import defaultdict
import requests
from bs4 import BeautifulSoup
from typing import Set, Dict, List


class EnhancedReconnaissance:
    """
    Advanced reconnaissance combining:
    - Subdomain enumeration
    - Email and phone extraction
    - Parameter discovery
    - Endpoint mapping
    - Technology fingerprinting
    """

    def __init__(self, target_domain: str, session: requests.Session = None):
        self.target_domain = target_domain.lower().strip()
        self.session = session or self._create_session()
        self.lock = threading.Lock()

        # Data stores
        self.subdomains: Set[str] = set()
        self.emails: Set[str] = set()
        self.phone_numbers: Set[str] = set()
        self.parameters: Dict[str, Set[str]] = defaultdict(set)
        self.technologies: Set[str] = set()
        self.sensitive_files: Set[str] = set()
        self.api_endpoints: Set[str] = set()

        # Regex patterns
        self.email_pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
        self.phone_pattern = re.compile(r'\b(?:\+?1[-.]?)?\(?\d{3}\)?[-.]?\d{3}[-.]?\d{4}\b')
        self.subdomain_pattern = re.compile(r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+' +
                                           re.escape(self.target_domain))

        # Technology fingerprints
        self.tech_signatures = {
            'WordPress': ['/wp-content/', '/wp-includes/', '/wp-admin/'],
            'Drupal': ['/sites/default/', '/modules/', '/themes/'],
            'Joomla': ['/administrator/', '/components/', '/modules/'],
            'React': ['react.js', 'react-dom.js', '__REACT_DEVTOOLS'],
            'Angular': ['ng-app', 'angular.js', 'ng-controller'],
            'Vue.js': ['vue.js', 'v-if', 'v-for'],
            'Django': ['csrfmiddlewaretoken', '/admin/', '__admin__'],
            'Flask': ['Werkzeug', 'flask'],
            'Express': ['x-powered-by: Express'],
            'Laravel': ['/vendor/laravel/', 'laravel_session'],
            'Spring': ['Whitelabel Error Page', 'Spring Framework'],
            'ASP.NET': ['__VIEWSTATE', 'aspx', 'ASP.NET'],
        }

        # Sensitive file patterns
        self.sensitive_patterns = [
            r'\.env', r'config\.php', r'\.git/', r'\.svn/',
            r'web\.config', r'\.htaccess', r'backup', r'\.sql',
            r'\.bak', r'admin', r'phpinfo', r'test'
        ]

    def _create_session(self) -> requests.Session:
        """Create a configured requests session"""
        session = requests.Session()
        session.headers.update({
            'User-Agent': 'BlackWidow/2.0 Security Scanner',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        })
        return session

    def analyze_page(self, url: str, html_content: str):
        """
        Comprehensive page analysis to extract intelligence

        Args:
            url: Page URL
            html_content: Raw HTML content
        """
        try:
            # Extract emails
            emails = self.email_pattern.findall(html_content)
            with self.lock:
                self.emails.update(emails)

            # Extract phone numbers
            phones = self.phone_pattern.findall(html_content)
            with self.lock:
                self.phone_numbers.update(phones)

            # Extract subdomains
            subdomains = self.subdomain_pattern.findall(html_content)
            with self.lock:
                self.subdomains.update(subdomains)

            # Parse with BeautifulSoup
            soup = BeautifulSoup(html_content, 'html.parser')

            # Extract URL parameters
            self._extract_parameters(url, soup)

            # Identify technologies
            self._identify_technologies(html_content, soup)

            # Find API endpoints
            self._find_api_endpoints(html_content, soup)

            # Detect sensitive files
            self._detect_sensitive_files(soup)

            logging.debug(f"Reconnaissance analysis completed for {url}")

        except Exception as e:
            logging.error(f"Error analyzing page {url}: {str(e)}")

    def _extract_parameters(self, url: str, soup: BeautifulSoup):
        """Extract URL and form parameters"""
        try:
            # URL parameters
            parsed = urlparse(url)
            if parsed.query:
                params = parse_qs(parsed.query)
                with self.lock:
                    for param in params.keys():
                        self.parameters[parsed.path].add(param)

            # Form parameters
            for form in soup.find_all('form'):
                action = form.get('action', parsed.path)
                full_action = urljoin(url, action)
                action_path = urlparse(full_action).path

                for input_tag in form.find_all(['input', 'textarea', 'select']):
                    param_name = input_tag.get('name')
                    if param_name:
                        with self.lock:
                            self.parameters[action_path].add(param_name)

        except Exception as e:
            logging.error(f"Error extracting parameters: {str(e)}")

    def _identify_technologies(self, html_content: str, soup: BeautifulSoup):
        """Identify technologies used by the target"""
        try:
            for tech, signatures in self.tech_signatures.items():
                for sig in signatures:
                    if sig.lower() in html_content.lower():
                        with self.lock:
                            self.technologies.add(tech)
                        break

            # Check meta tags
            for meta in soup.find_all('meta'):
                generator = meta.get('name', '').lower()
                if generator == 'generator':
                    content = meta.get('content', '')
                    if content:
                        with self.lock:
                            self.technologies.add(content)

            # Check script sources for CDN usage
            for script in soup.find_all('script', src=True):
                src = script['src'].lower()
                if 'jquery' in src:
                    self.technologies.add('jQuery')
                elif 'bootstrap' in src:
                    self.technologies.add('Bootstrap')
                elif 'vue' in src:
                    self.technologies.add('Vue.js')
                elif 'react' in src:
                    self.technologies.add('React')
                elif 'angular' in src:
                    self.technologies.add('Angular')

        except Exception as e:
            logging.error(f"Error identifying technologies: {str(e)}")

    def _find_api_endpoints(self, html_content: str, soup: BeautifulSoup):
        """Discover API endpoints"""
        try:
            # Common API patterns
            api_patterns = [
                r'/api/v?\d*/[\w/-]+',
                r'/rest/[\w/-]+',
                r'/graphql',
                r'/v\d+/[\w/-]+',
            ]

            for pattern in api_patterns:
                matches = re.findall(pattern, html_content)
                with self.lock:
                    self.api_endpoints.update(matches)

            # Check script contents for API calls
            for script in soup.find_all('script'):
                if script.string:
                    # Look for fetch/axios/ajax calls
                    api_calls = re.findall(
                        r'(?:fetch|axios|ajax)\s*\(\s*[\'"]([^\'"]+)[\'"]',
                        script.string
                    )
                    with self.lock:
                        self.api_endpoints.update(api_calls)

        except Exception as e:
            logging.error(f"Error finding API endpoints: {str(e)}")

    def _detect_sensitive_files(self, soup: BeautifulSoup):
        """Detect potentially sensitive files and endpoints"""
        try:
            for link in soup.find_all(['a', 'link', 'script'], href=True):
                href = link.get('href', '') or link.get('src', '')
                for pattern in self.sensitive_patterns:
                    if re.search(pattern, href, re.IGNORECASE):
                        with self.lock:
                            self.sensitive_files.add(href)
                        break

        except Exception as e:
            logging.error(f"Error detecting sensitive files: {str(e)}")

    def get_summary(self) -> Dict:
        """Get reconnaissance summary"""
        return {
            'subdomains': sorted(list(self.subdomains)),
            'emails': sorted(list(self.emails)),
            'phone_numbers': sorted(list(self.phone_numbers)),
            'parameters': {k: sorted(list(v)) for k, v in self.parameters.items()},
            'technologies': sorted(list(self.technologies)),
            'sensitive_files': sorted(list(self.sensitive_files)),
            'api_endpoints': sorted(list(self.api_endpoints)),
            'stats': {
                'subdomain_count': len(self.subdomains),
                'email_count': len(self.emails),
                'phone_count': len(self.phone_numbers),
                'parameter_count': sum(len(v) for v in self.parameters.values()),
                'technology_count': len(self.technologies),
                'api_endpoint_count': len(self.api_endpoints),
            }
        }
