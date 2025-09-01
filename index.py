import socket
import ssl
import requests
import urllib.parse
from urllib.parse import urlparse, urljoin
import re
import json
from datetime import datetime
import concurrent.futures
import time
import colorama
from colorama import Fore, Style
import os

# Initialize colorama for colored output
colorama.init(autoreset=True)

def get_domain_from_url(url):
    """Extract domain from URL"""
    parsed_url = urlparse(url)
    return parsed_url.netloc

def get_base_url(url):
    """Get base URL without path"""
    parsed_url = urlparse(url)
    return f"{parsed_url.scheme}://{parsed_url.netloc}"

def port_scan(url, port_range=(1, 1024), common_ports=[80, 443, 8080, 8443, 3306, 5432, 3389, 22, 21]):
    """Scan for open ports on the target website using threading for faster scanning"""
    domain = get_domain_from_url(url)
    open_ports = []
    
    # Combine common ports with the specified range
    ports_to_scan = set(common_ports)
    ports_to_scan.update(range(port_range[0], port_range[1] + 1))
    
    def check_port(port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((domain, port))
            sock.close()
            return port if result == 0 else None
        except:
            return None
    
    # Use ThreadPoolExecutor for parallel port scanning
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        future_to_port = {executor.submit(check_port, port): port for port in ports_to_scan}
        
        for future in concurrent.futures.as_completed(future_to_port):
            port = future_to_port[future]
            try:
                result = future.result()
                if result:
                    open_ports.append(result)
            except Exception as e:
                print(f"Error scanning port {port}: {e}")
    
    return sorted(open_ports)

def check_ssl(url):
    """Validate SSL certificate and check for weak protocols"""
    domain = get_domain_from_url(url)
    
    ssl_info = {
        'valid': False,
        'weak_protocols': [],
        'self_signed': False,
        'error': None
    }
    
    # Test different SSL/TLS protocols
    protocols = {
        'SSLv2': ssl.PROTOCOL_SSLv2,
        'SSLv3': ssl.PROTOCOL_SSLv3,
        'TLSv1': ssl.PROTOCOL_TLSv1,
        'TLSv1.1': ssl.PROTOCOL_TLSv1_1,
        'TLSv1.2': ssl.PROTOCOL_TLSv1_2
    }
    
    for name, protocol in protocols.items():
        try:
            context = ssl.SSLContext(protocol)
            context.verify_mode = ssl.CERT_REQUIRED
            context.check_hostname = True
            context.load_default_certs()
            
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    # If we get here, the protocol is supported
                    if name in ['SSLv2', 'SSLv3', 'TLSv1']:
                        ssl_info['weak_protocols'].append(name)
        except:
            pass  # Protocol not supported
    
    # Get certificate details
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                
                # Check certificate expiration
                expiry_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                days_until_expiry = (expiry_date - datetime.now()).days
                
                # Check if certificate is self-signed
                issuer = dict(x[0] for x in cert['issuer'])
                subject = dict(x[0] for x in cert['subject'])
                ssl_info['self_signed'] = issuer == subject
                
                # Check if certificate is valid
                ssl_info.update({
                    'valid': True,
                    'issuer': issuer,
                    'subject': subject,
                    'expiry_date': expiry_date.strftime('%Y-%m-%d'),
                    'days_until_expiry': days_until_expiry,
                    'version': cert.get('version'),
                    'serialNumber': cert.get('serialNumber')
                })
    except Exception as e:
        ssl_info['error'] = str(e)
    
    return ssl_info

def check_headers(url):
    """Check for important security headers and validate against best practices"""
    headers_to_check = [
        'Content-Security-Policy',
        'X-Frame-Options',
        'Strict-Transport-Security',
        'X-Content-Type-Options',
        'X-XSS-Protection',
        'Referrer-Policy',
        'Permissions-Policy'
    ]
    
    try:
        response = requests.get(url, timeout=10, allow_redirects=True)
        headers = response.headers
        
        results = {}
        for header in headers_to_check:
            if header in headers:
                value = headers[header]
                results[header] = {
                    'present': True,
                    'value': value,
                    'compliance': check_header_compliance(header, value)
                }
            else:
                results[header] = {
                    'present': False,
                    'value': None,
                    'compliance': {'status': 'missing', 'issues': ['Header not present']}
                }
        
        return results
    except Exception as e:
        return {'error': str(e)}

def check_header_compliance(header, value):
    """Check if a header value complies with security best practices"""
    issues = []
    status = "good"
    
    if header == 'Content-Security-Policy':
        if "'unsafe-inline'" in value:
            issues.append("CSP allows unsafe-inline")
            status = "warning"
        if "'unsafe-eval'" in value:
            issues.append("CSP allows unsafe-eval")
            status = "warning"
        if not any(directive in value for directive in ["default-src", "script-src", "object-src"]):
            issues.append("CSP missing important directives")
            status = "warning"
    
    elif header == 'Strict-Transport-Security':
        if 'max-age' not in value:
            issues.append("HSTS missing max-age directive")
            status = "warning"
        elif 'max-age=0' in value:
            issues.append("HSTS max-age is set to 0 (disables HSTS)")
            status = "bad"
        elif not 'includeSubDomains' in value:
            issues.append("HSTS missing includeSubDomains directive")
            status = "warning"
        elif not 'preload' in value:
            issues.append("HSTS missing preload directive")
            status = "info"
    
    elif header == 'X-Frame-Options':
        if value.upper() not in ['DENY', 'SAMEORIGIN']:
            issues.append(f"X-Frame-Options should be DENY or SAMEORIGIN, got {value}")
            status = "bad"
    
    elif header == 'X-XSS-Protection':
        if '0' in value:
            issues.append("X-XSS-Protection is disabled")
            status = "bad"
        elif 'mode=block' not in value:
            issues.append("X-XSS-Protection missing mode=block")
            status = "warning"
    
    return {'status': status, 'issues': issues}

def test_sql_injection(url):
    """Test for basic SQL injection vulnerabilities including time-based blind SQLi"""
    # Basic SQL injection payloads
    payloads = [
        {"payload": "' OR '1'='1", "type": "boolean"},
        {"payload": "' OR 1=1--", "type": "boolean"},
        {"payload": "'; DROP TABLE users;--", "type": "error"},
        {"payload": "' UNION SELECT NULL--", "type": "union"},
        {"payload": "' OR SLEEP(5)--", "type": "time-based"}
    ]
    
    parsed_url = urlparse(url)
    query_params = urllib.parse.parse_qs(parsed_url.query)
    
    vulnerabilities = []
    
    if not query_params:
        return vulnerabilities
    
    for param in query_params:
        original_value = query_params[param][0]
        
        for payload_data in payloads:
            payload = payload_data["payload"]
            payload_type = payload_data["type"]
            
            try:
                # Replace parameter value with payload
                modified_params = query_params.copy()
                modified_params[param] = [payload]
                
                # Reconstruct URL
                new_query = urllib.parse.urlencode(modified_params, doseq=True)
                target_url = urllib.parse.urlunparse((
                    parsed_url.scheme,
                    parsed_url.netloc,
                    parsed_url.path,
                    parsed_url.params,
                    new_query,
                    parsed_url.fragment
                ))
                
                # Send request and measure time for time-based SQLi
                start_time = time.time()
                response = requests.get(target_url, timeout=15)
                response_time = time.time() - start_time
                
                # Check for common SQL error patterns
                error_patterns = [
                    r"sql.*error",
                    r"syntax.*error",
                    r"mysql.*error",
                    r"ora-[0-9]",
                    r"unclosed.*quotation",
                    r"quoted.*string",
                ]
                
                evidence = None
                
                if payload_type == "time-based" and response_time > 5:
                    evidence = f"Time-based delay detected ({response_time:.2f}s)"
                else:
                    for pattern in error_patterns:
                        if re.search(pattern, response.text, re.IGNORECASE):
                            evidence = 'SQL error message found in response'
                            break
                
                if evidence:
                    vulnerabilities.append({
                        'parameter': param,
                        'payload': payload,
                        'type': payload_type,
                        'evidence': evidence
                    })
                        
            except Exception as e:
                continue
    
    return vulnerabilities

def test_xss(url):
    """Test for basic XSS vulnerabilities including DOM-based XSS"""
    # Basic XSS payloads
    payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        "'\"><script>alert('XSS')</script>",
        "javascript:alert('XSS')"
    ]
    
    parsed_url = urlparse(url)
    query_params = urllib.parse.parse_qs(parsed_url.query)
    
    vulnerabilities = []
    
    # Test query parameters
    if query_params:
        for param in query_params:
            original_value = query_params[param][0]
            
            for payload in payloads:
                try:
                    # Replace parameter value with payload
                    modified_params = query_params.copy()
                    modified_params[param] = [payload]
                    
                    # Reconstruct URL
                    new_query = urllib.parse.urlencode(modified_params, doseq=True)
                    target_url = urllib.parse.urlunparse((
                        parsed_url.scheme,
                        parsed_url.netloc,
                        parsed_url.path,
                        parsed_url.params,
                        new_query,
                        parsed_url.fragment
                    ))
                    
                    # Send request
                    response = requests.get(target_url, timeout=10)
                    
                    # Check if payload is reflected in response
                    if payload in response.text:
                        # Check if payload is executed in DOM context
                        dom_context = check_dom_xss(response.text, payload)
                        
                        vulnerabilities.append({
                            'parameter': param,
                            'payload': payload,
                            'evidence': 'Payload reflected in response',
                            'dom_based': dom_context
                        })
                            
                except Exception as e:
                    continue
    
    # Test URL fragment for DOM-based XSS
    for payload in payloads:
        try:
            fragment_url = urllib.parse.urlunparse((
                parsed_url.scheme,
                parsed_url.netloc,
                parsed_url.path,
                parsed_url.params,
                parsed_url.query,
                payload
            ))
            
            response = requests.get(fragment_url, timeout=10)
            
            # Check if payload appears in JavaScript context
            if check_dom_xss(response.text, payload):
                vulnerabilities.append({
                    'parameter': 'URL Fragment',
                    'payload': payload,
                    'evidence': 'DOM-based XSS potential in fragment',
                    'dom_based': True
                })
                    
        except Exception as e:
            continue
    
    return vulnerabilities

def check_dom_xss(html_content, payload):
    """Check if payload appears in DOM context (JavaScript)"""
    # Patterns to find JavaScript contexts
    js_patterns = [
        r'<script[^>]*>(.*?)</script>',  # Script tags
        r'on\w+\s*=\s*["\'](.*?)["\']',  # Event handlers
        r'javascript:\s*(.*?)["\'\s]',   # JavaScript URLs
    ]
    
    for pattern in js_patterns:
        matches = re.finditer(pattern, html_content, re.IGNORECASE | re.DOTALL)
        for match in matches:
            if payload in match.group(1):
                return True
    
    return False

def check_cors(url):
    """Check for CORS misconfigurations"""
    try:
        # Test with arbitrary origin
        headers = {'Origin': 'https://evil.com'}
        response = requests.get(url, headers=headers, timeout=10)
        
        cors_headers = {}
        if 'Access-Control-Allow-Origin' in response.headers:
            cors_headers['Access-Control-Allow-Origin'] = response.headers['Access-Control-Allow-Origin']
        
        if 'Access-Control-Allow-Credentials' in response.headers:
            cors_headers['Access-Control-Allow-Credentials'] = response.headers['Access-Control-Allow-Credentials']
        
        vulnerabilities = []
        
        # Check for misconfigurations
        if 'Access-Control-Allow-Origin' in cors_headers:
            if cors_headers['Access-Control-Allow-Origin'] == '*':
                if 'Access-Control-Allow-Credentials' in cors_headers and \
                   cors_headers['Access-Control-Allow-Credentials'].lower() == 'true':
                    vulnerabilities.append({
                        'type': 'CORS',
                        'issue': 'Allow-Origin set to * with Allow-Credentials true',
                        'severity': 'high'
                    })
                else:
                    vulnerabilities.append({
                        'type': 'CORS',
                        'issue': 'Allow-Origin set to *',
                        'severity': 'medium'
                    })
            elif cors_headers['Access-Control-Allow-Origin'] == 'https://evil.com':
                vulnerabilities.append({
                    'type': 'CORS',
                    'issue': 'Reflects arbitrary Origin header',
                    'severity': 'high'
                })
        
        return vulnerabilities
    except Exception as e:
        return [{'type': 'CORS', 'issue': f'Error testing CORS: {str(e)}', 'severity': 'info'}]

def check_directory_traversal(url):
    """Check for common sensitive files and directories"""
    sensitive_paths = [
        '/.git/HEAD',
        '/.env',
        '/robots.txt',
        '/.htaccess',
        '/admin/',
        '/wp-admin/',
        '/backup/',
        '/config/',
        '/phpinfo.php',
        '/server-status'
    ]
    
    found_paths = []
    base_url = get_base_url(url)
    
    for path in sensitive_paths:
        try:
            test_url = base_url + path
            response = requests.get(test_url, timeout=5)
            
            if response.status_code == 200:
                found_paths.append({
                    'path': path,
                    'url': test_url,
                    'status': response.status_code,
                    'length': len(response.content)
                })
        except:
            pass
    
    return found_paths

def check_clickjacking(url):
    """Check if the site is vulnerable to clickjacking"""
    try:
        response = requests.get(url, timeout=10)
        headers = response.headers
        
        if 'X-Frame-Options' in headers:
            value = headers['X-Frame-Options'].upper()
            if value in ['DENY', 'SAMEORIGIN']:
                return {
                    'vulnerable': False,
                    'protection': f'X-Frame-Options: {value}'
                }
        
        # Check for CSP frame-ancestors directive
        if 'Content-Security-Policy' in headers:
            csp = headers['Content-Security-Policy']
            if 'frame-ancestors' in csp and 'none' in csp:
                return {
                    'vulnerable': False,
                    'protection': 'CSP frame-ancestors directive present'
                }
        
        return {
            'vulnerable': True,
            'issue': 'No clickjacking protection headers found'
        }
    except Exception as e:
        return {
            'vulnerable': False,
            'error': str(e)
        }

def print_report(url, port_results, ssl_results, header_results, sql_results, xss_results, 
                cors_results, dir_results, clickjacking_results, output_format='console'):
    """Print a comprehensive security report in various formats"""
    
    report_data = {
        'url': url,
        'scan_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'open_ports': port_results,
        'ssl': ssl_results,
        'headers': header_results,
        'sql_injection': sql_results,
        'xss': xss_results,
        'cors': cors_results,
        'sensitive_paths': dir_results,
        'clickjacking': clickjacking_results
    }
    
    if output_format == 'json':
        # Save as JSON
        filename = f"security_scan_{urlparse(url).netloc}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w') as f:
            json.dump(report_data, f, indent=2)
        print(f"{Fore.GREEN}Report saved to {filename}{Style.RESET_ALL}")
        return
    
    if output_format == 'html':
        # Generate HTML report
        generate_html_report(report_data)
        return
    
    # Console output
    print(Fore.CYAN + "=" * 80)
    print("SECURITY SCAN REPORT")
    print("=" * 80)
    print(f"Target URL: {url}")
    print(f"Scan date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 80)
    
    # Port scan results
    print(f"\n{Fore.YELLOW}1. OPEN PORTS SCAN{Style.RESET_ALL}")
    print("-" * 40)
    if port_results:
        print(f"{Fore.RED}Open ports found: {', '.join(map(str, port_results))}{Style.RESET_ALL}")
    else:
        print(f"{Fore.GREEN}No open ports found from the scanned range.{Style.RESET_ALL}")
    
    # SSL results
    print(f"\n{Fore.YELLOW}2. SSL CERTIFICATE CHECK{Style.RESET_ALL}")
    print("-" * 40)
    if 'error' in ssl_results:
        print(f"{Fore.RED}Error: {ssl_results['error']}{Style.RESET_ALL}")
    elif not ssl_results.get('valid', False):
        print(f"{Fore.RED}SSL certificate is invalid or could not be verified.{Style.RESET_ALL}")
    else:
        print(f"{Fore.GREEN}SSL certificate is valid.{Style.RESET_ALL}")
        print(f"Issuer: {ssl_results.get('issuer', {}).get('organizationName', 'Unknown')}")
        print(f"Subject: {ssl_results.get('subject', {}).get('commonName', 'Unknown')}")
        print(f"Expiry date: {ssl_results.get('expiry_date')}")
        print(f"Days until expiry: {ssl_results.get('days_until_expiry')}")
        
        if ssl_results.get('self_signed'):
            print(f"{Fore.RED}Certificate is self-signed.{Style.RESET_ALL}")
        
        if ssl_results.get('weak_protocols'):
            print(f"{Fore.RED}Weak protocols supported: {', '.join(ssl_results['weak_protocols'])}{Style.RESET_ALL}")
    
    # Header results
    print(f"\n{Fore.YELLOW}3. SECURITY HEADERS CHECK{Style.RESET_ALL}")
    print("-" * 40)
    if 'error' in header_results:
        print(f"{Fore.RED}Error: {header_results['error']}{Style.RESET_ALL}")
    else:
        for header, data in header_results.items():
            if data['present']:
                status_color = Fore.GREEN if data['compliance']['status'] == 'good' else \
                              Fore.YELLOW if data['compliance']['status'] == 'warning' else \
                              Fore.RED
                print(f"{status_color}{header}: {data['value']}{Style.RESET_ALL}")
                
                for issue in data['compliance']['issues']:
                    print(f"  {Fore.YELLOW}⚠ {issue}{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}{header}: MISSING{Style.RESET_ALL}")
    
    # SQL injection results
    print(f"\n{Fore.YELLOW}4. SQL INJECTION TEST{Style.RESET_ALL}")
    print("-" * 40)
    if sql_results:
        print(f"{Fore.RED}{len(sql_results)} potential vulnerabilities found!{Style.RESET_ALL}")
        for vuln in sql_results:
            print(f"{Fore.RED}Parameter: {vuln['parameter']}")
            print(f"Payload: {vuln['payload']}")
            print(f"Type: {vuln['type']}")
            print(f"Evidence: {vuln['evidence']}{Style.RESET_ALL}")
            print()
    else:
        print(f"{Fore.GREEN}No SQL injection vulnerabilities detected.{Style.RESET_ALL}")
    
    # XSS results
    print(f"\n{Fore.YELLOW}5. CROSS-SITE SCRIPTING (XSS) TEST{Style.RESET_ALL}")
    print("-" * 40)
    if xss_results:
        print(f"{Fore.RED}{len(xss_results)} potential vulnerabilities found!{Style.RESET_ALL}")
        for vuln in xss_results:
            print(f"{Fore.RED}Parameter: {vuln['parameter']}")
            print(f"Payload: {vuln['payload']}")
            print(f"Evidence: {vuln['evidence']}")
            if vuln.get('dom_based'):
                print(f"DOM-based: {vuln['dom_based']}{Style.RESET_ALL}")
            print()
    else:
        print(f"{Fore.GREEN}No XSS vulnerabilities detected.{Style.RESET_ALL}")
    
    # CORS results
    print(f"\n{Fore.YELLOW}6. CORS MISCONFIGURATION CHECK{Style.RESET_ALL}")
    print("-" * 40)
    if cors_results:
        for issue in cors_results:
            severity_color = Fore.RED if issue['severity'] == 'high' else \
                            Fore.YELLOW if issue['severity'] == 'medium' else \
                            Fore.BLUE
            print(f"{severity_color}{issue['type']}: {issue['issue']} (Severity: {issue['severity']}){Style.RESET_ALL}")
    else:
        print(f"{Fore.GREEN}No CORS misconfigurations detected.{Style.RESET_ALL}")
    
    # Directory traversal results
    print(f"\n{Fore.YELLOW}7. SENSITIVE PATHS CHECK{Style.RESET_ALL}")
    print("-" * 40)
    if dir_results:
        print(f"{Fore.YELLOW}{len(dir_results)} sensitive paths found:{Style.RESET_ALL}")
        for path in dir_results:
            print(f"{Fore.YELLOW}{path['path']} - Status: {path['status']}, Length: {path['length']}{Style.RESET_ALL}")
    else:
        print(f"{Fore.GREEN}No sensitive paths found.{Style.RESET_ALL}")
    
    # Clickjacking results
    print(f"\n{Fore.YELLOW}8. CLICKJACKING TEST{Style.RESET_ALL}")
    print("-" * 40)
    if clickjacking_results.get('vulnerable'):
        print(f"{Fore.RED}Vulnerable to clickjacking: {clickjacking_results.get('issue')}{Style.RESET_ALL}")
    elif clickjacking_results.get('error'):
        print(f"{Fore.YELLOW}Error testing clickjacking: {clickjacking_results.get('error')}{Style.RESET_ALL}")
    else:
        print(f"{Fore.GREEN}Protected against clickjacking: {clickjacking_results.get('protection')}{Style.RESET_ALL}")
    
    print(Fore.CYAN + "=" * 80)
    print("SCAN COMPLETE")
    print("=" * 80)

def generate_html_report(report_data):
    """Generate an HTML report of the security scan"""
    filename = f"security_scan_{urlparse(report_data['url']).netloc}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    
    html_template = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Security Scan Report - {report_data['url']}</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 40px; }}
            h1 {{ color: #333; }}
            h2 {{ color: #555; border-bottom: 1px solid #ddd; padding-bottom: 10px; }}
            .vulnerable {{ color: #d9534f; }}
            .secure {{ color: #5cb85c; }}
            .warning {{ color: #f0ad4e; }}
            .info {{ color: #5bc0de; }}
            table {{ border-collapse: collapse; width: 100%; margin-bottom: 20px; }}
            th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
            th {{ background-color: #f2f2f2; }}
            tr:nth-child(even) {{ background-color: #f9f9f9; }}
        </style>
    </head>
    <body>
        <h1>Security Scan Report</h1>
        <p><strong>Target URL:</strong> {report_data['url']}</p>
        <p><strong>Scan Date:</strong> {report_data['scan_date']}</p>
        
        <h2>Open Ports</h2>
        <p>{', '.join(map(str, report_data['open_ports'])) if report_data['open_ports'] else 'No open ports found'}</p>
        
        <h2>SSL Certificate</h2>
        <p>
            Valid: {'Yes' if report_data['ssl'].get('valid') else 'No'}<br>
            Issuer: {report_data['ssl'].get('issuer', {}).get('organizationName', 'Unknown')}<br>
            Expiry: {report_data['ssl'].get('expiry_date', 'Unknown')}<br>
            Weak Protocols: {', '.join(report_data['ssl'].get('weak_protocols', [])) or 'None'}<br>
            Self-Signed: {'Yes' if report_data['ssl'].get('self_signed') else 'No'}
        </p>
        
        <h2>Security Headers</h2>
        <table>
            <tr><th>Header</th><th>Value</th><th>Status</th></tr>
            {"".join([f"<tr><td>{header}</td><td>{data.get('value', 'MISSING')}</td><td class={'warning' if data.get('compliance', {}).get('status') == 'warning' else 'secure' if data.get('present') else 'vulnerable'}>{'OK' if data.get('present') and data.get('compliance', {}).get('status') == 'good' else 'WARNING' if data.get('compliance', {}).get('status') == 'warning' else 'MISSING'}</td></tr>" for header, data in report_data['headers'].items() if not isinstance(report_data['headers'], dict) or 'error' not in report_data['headers']])}
        </table>
        
        <h2>SQL Injection Vulnerabilities</h2>
        <table>
            <tr><th>Parameter</th><th>Payload</th><th>Evidence</th></tr>
            {"".join([f"<tr class='vulnerable'><td>{vuln['parameter']}</td><td>{vuln['payload']}</td><td>{vuln['evidence']}</td></tr>" for vuln in report_data['sql_injection']]) if report_data['sql_injection'] else "<tr><td colspan='3'>No vulnerabilities found</td></tr>"}
        </table>
        
        <h2>XSS Vulnerabilities</h2>
        <table>
            <tr><th>Parameter</th><th>Payload</th><th>Evidence</th></tr>
            {"".join([f"<tr class='vulnerable'><td>{vuln['parameter']}</td><td>{vuln['payload']}</td><td>{vuln['evidence']}</td></tr>" for vuln in report_data['xss']]) if report_data['xss'] else "<tr><td colspan='3'>No vulnerabilities found</td></tr>"}
        </table>
        
        <h2>CORS Misconfigurations</h2>
        <table>
            <tr><th>Issue</th><th>Severity</th></tr>
            {"".join([f"<tr class={'vulnerable' if issue['severity'] == 'high' else 'warning' if issue['severity'] == 'medium' else 'info'}'><td>{issue['issue']}</td><td>{issue['severity']}</td></tr>" for issue in report_data['cors']]) if report_data['cors'] else "<tr><td colspan='2'>No misconfigurations found</td></tr>"}
        </table>
        
        <h2>Sensitive Paths</h2>
        <table>
            <tr><th>Path</th><th>Status</th><th>Length</th></tr>
            {"".join([f"<tr class='warning'><td>{path['path']}</td><td>{path['status']}</td><td>{path['length']}</td></tr>" for path in report_data['sensitive_paths']]) if report_data['sensitive_paths'] else "<tr><td colspan='3'>No sensitive paths found</td></tr>"}
        </table>
        
        <h2>Clickjacking Protection</h2>
        <p class={'secure' if not report_data['clickjacking'].get('vulnerable') else 'vulnerable'}>
            {report_data['clickjacking'].get('protection', 'Vulnerable to clickjacking')}
        </p>
    </body>
    </html>
    """
    
    with open(filename, 'w') as f:
        f.write(html_template)
    
    print(f"{Fore.GREEN}HTML report saved to {filename}{Style.RESET_ALL}")

def main():
    """Main function to run the security scanner"""
    print(Fore.CYAN + "Website Security Scanner")
    print("=" * 30)
    
    # Get URL from user
    url = input("Enter the website URL to scan: ").strip()
    
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    # Get output format
    output_format = input("Output format (console/json/html): ").strip().lower()
    if output_format not in ['console', 'json', 'html']:
        output_format = 'console'
    
    try:
        # Validate URL
        response = requests.head(url, timeout=10, allow_redirects=True)
        if response.status_code >= 400:
            print(f"{Fore.RED}Error: Website returned status code {response.status_code}{Style.RESET_ALL}")
            return
        
        print(f"Scanning {url}...")
        
        # Perform security checks
        print("Checking open ports...")
        ports = port_scan(url)
        
        print("Checking SSL certificate...")
        ssl_info = check_ssl(url)
        
        print("Checking security headers...")
        headers = check_headers(url)
        
        print("Testing for SQL injection...")
        sql_vulns = test_sql_injection(url)
        
        print("Testing for XSS...")
        xss_vulns = test_xss(url)
        
        print("Checking for CORS misconfigurations...")
        cors_vulns = check_cors(url)
        
        print("Checking for sensitive paths...")
        dir_traversal = check_directory_traversal(url)
        
        print("Testing for clickjacking...")
        clickjacking = check_clickjacking(url)
        
        # Generate report
        print_report(url, ports, ssl_info, headers, sql_vulns, xss_vulns, 
                    cors_vulns, dir_traversal, clickjacking, output_format)
        
    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED}Error connecting to {url}: {e}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}An unexpected error occurred: {e}{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
