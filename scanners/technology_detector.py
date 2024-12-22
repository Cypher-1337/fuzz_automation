import subprocess
import requests
from bs4 import BeautifulSoup, Comment
import re
from utils.color_print import ColorPrint
import hashlib
import base64

class TechnologyDetector:
    def __init__(self):
        self.important_security_headers = [
            'X-Frame-Options',
            'X-Content-Type-Options',
            'X-XSS-Protection',
            'Content-Security-Policy',
            'Strict-Transport-Security',
            'Referrer-Policy'
        ]
        self.tech_fingerprints = {
            "WordPress": [
                re.compile(r'wp-content'),
                re.compile(r'wp-admin'),
                re.compile(r'WordPress')
            ],
            "Joomla": [
                re.compile(r'index.php\?option=com_'),
                re.compile(r'Joomla!')
            ],
            "Drupal": [
                re.compile(r'Drupal'),
                re.compile(r'Powered by Drupal')
            ],
            "Magento": [
                re.compile(r'skin/frontend/'),
                re.compile(r'Magento')
            ],
            "PHPMyAdmin": [
                re.compile(r'phpMyAdmin')
            ],
            "Apache": [
                re.compile(r'Apache')
            ],
            "Nginx": [
                re.compile(r'nginx')
            ],
            "IIS": [
                re.compile(r'Microsoft-IIS')
            ],
            "React": [
                re.compile(r'_reactRoot'),
                re.compile(r'createElement'),
                re.compile(r'react-dom\.production\.min\.js'), # Common React library file
            ],
            "Vue.js": [
                re.compile(r'new Vue'),
                re.compile(r'vue\.runtime\.esm\.js') # Common Vue library file
            ],
            "Angular": [
                re.compile(r'ng-version'),
                re.compile(r'angular\.js') # Common Angular library file
            ],
            "Node.js": [
                re.compile(r'X-Powered-By.*Node\.js', re.IGNORECASE)
            ],
            "ASP.NET": [
                re.compile(r'ASP.NET'),
                re.compile(r'__VIEWSTATE')
            ],
            "Ruby on Rails": [
                re.compile(r'action_controller\.params'),
                re.compile(r'railties')
            ],
            "PHP": [
                re.compile(r'PHP/\d+\.\d+\.\d+')
            ],
            "Next.js": [
                re.compile(r'/_next/static/'),
                re.compile(r'data-precedence="next"'),
                re.compile(r'__next_f=')
            ],
            "Styled Components": [
                re.compile(r'data-styled="true"'),
                re.compile(r'data-styled-version="[\d\.]+"')
            ],
            "Stripe": [
                re.compile(r'https://js\.stripe\.com/v\d+/'),
                re.compile(r'stripe\.confirmCardPayment')
            ],
            "JQuery": [
                re.compile(r'jquery-[\d\.]+\.min\.js')
            ],
            "Bootstrap": [
                re.compile(r'bootstrap\.min\.css'),
                re.compile(r'bootstrap\.bundle\.min\.js')
            ],
            "Font Awesome": [
                re.compile(r'fontawesome-free/\w+\.css'),
                re.compile(r'fa-')
            ]
            # Add more fingerprints here
        }
        self.favicon_hashes = {
            # WordPress
            "S4mrNEqmBPjL4UeBPixCVA==": "WordPress",
            "S4mrNEqmBPjL4UeBPixCVA=": "WordPress", # Handle potential padding differences

            # React (Create React App default)
            "koDiTOrf19VUmN01uHMedw==": "React",
            "koDiTOrf19VUmN01uHMedw=": "React", # Handle potential padding differences

            # Next.js (Vercel's default)
            "sA3SxlmYrk6ykvjSZpdPHA==": "Next.js",
            "sA3SxlmYrk6ykvjSZpdPHA=": "Next.js", # Handle potential padding differences

            # Example for another common technology - PHP
            "2n1QSm5VFQ6g5rwlhU3CuQ==": "PHP",
            "2n1QSm5VFQ6g5rwlhU3CuQ=": "PHP", # Handle potential padding differences

            # Add more favicon hashes and their corresponding technologies (use SHA-256 base64 encoded)
        }

    def detect_technology(self, subdomain):
        """Detect the technology stack of a subdomain using multiple tools."""
        try:
            tech_details = {}
            tech_details["WhatWeb"] = self._run_whatweb(subdomain)
            tech_details["Wappalyzer"] = self._run_wappalyzer(subdomain)
            tech_details["SecurityScan"] = self._active_scan(subdomain)

            return self._determine_primary_technology(tech_details), tech_details

        except Exception as e:
            ColorPrint.error(f"Error detecting technology for {subdomain}: {str(e)}")
            return "general", {"Error": str(e)}

    def _run_whatweb(self, subdomain):
        try:
            result = subprocess.run(["whatweb", subdomain], capture_output=True, text=True)
            return result.stdout
        except subprocess.SubprocessError as e:
            return f"WhatWeb error: {str(e)}"

    def _run_wappalyzer(self, subdomain):
        try:
            result = subprocess.run(["wappalyzer", subdomain], capture_output=True, text=True)
            return result.stdout
        except (subprocess.SubprocessError, FileNotFoundError) as e:
            return f"Wappalyzer error: {str(e)}"

    def _active_scan(self, subdomain):
        security_info = {
            "server": {"name": "Unknown", "version": "Unknown"},
            "technologies": [],
            "headers": {},
            "security_headers_missing": [],
            "interesting_findings": [],
            "potential_vulnerabilities": []
        }

        try:
            get_response = requests.get(subdomain, timeout=10, allow_redirects=True)
            head_response = requests.head(subdomain, timeout=10, allow_redirects=True)
            options_response = requests.options(subdomain, timeout=10, allow_redirects=True)

            self._analyze_headers(security_info, get_response.headers)
            self._analyze_http_methods(security_info, options_response)
            self._analyze_html_content(security_info, get_response.content.decode('utf-8', errors='ignore'), get_response.url)
            self._analyze_favicon(security_info, get_response.url)

            return security_info

        except requests.RequestException as e:
            ColorPrint.error(f"Error during active scan of {subdomain}: {str(e)}")
            return security_info
        except Exception as e:
            ColorPrint.error(f"Unexpected error during active scan of {subdomain}: {str(e)}")
            return security_info

    def _analyze_headers(self, security_info, headers):
        if 'Server' in headers:
            server_header = headers['Server']
            security_info["server"]["name"] = server_header
            version_match = re.search(r'/([\d.]+)', server_header)
            if version_match:
                security_info["server"]["version"] = version_match.group(1)

        for header, value in headers.items():
            security_info["headers"][header] = value
            self._detect_technologies_from_header(security_info, header, value)

        self._check_missing_security_headers(security_info, headers)

        # More specific header checks
        if 'X-Powered-By' in headers:
            security_info["technologies"].append(f"X-Powered-By: {headers['X-Powered-By']}")
        if 'X-Generator' in headers:
            security_info["technologies"].append(f"X-Generator: {headers['X-Generator']}")
        if 'Set-Cookie' in headers and 'PHPSESSID' in headers['Set-Cookie']:
            security_info["technologies"].append("PHP")
        if 'Set-Cookie' in headers and 'JSESSIONID' in headers['Set-Cookie']:
            security_info["technologies"].append("JSP")
        if 'X-AspNet-Version' in headers:
            security_info["technologies"].append(f"ASP.NET: Version {headers['X-AspNet-Version']}")
        if 'X- স্টেশন' in headers:  # Example of a less common header
            security_info["technologies"].append(f"Probable Technology based on header: {headers['X- স্টেশন']}")

    def _detect_technologies_from_header(self, security_info, header, value):
        tech_indicators = {
            'PHP': 'PHP',
            'ASP.NET': 'ASP.NET',
            'JSP': 'JSP',
            'WordPress': 'WordPress',
            'Drupal': 'Drupal',
            'Joomla': 'Joomla',
            'Magento': 'Magento',
            'Next.js': 'Next.js',
            'React': 'React',
            'Vue.js': 'Vue.js',
            'Angular': 'Angular'
        }

        for indicator, tech in tech_indicators.items():
            if indicator.lower() in value.lower():
                security_info["technologies"].append(f"{tech} (Header)")

    def _check_missing_security_headers(self, security_info, headers):
        for header in self.important_security_headers:
            if header not in headers:
                security_info["security_headers_missing"].append(header)

    def _analyze_http_methods(self, security_info, options_response):
        if options_response.status_code == 200:
            allowed_methods = options_response.headers.get('Allow', '')
            dangerous_methods = ['PUT', 'DELETE', 'TRACE', 'TRACK']
            if any(method in allowed_methods for method in dangerous_methods):
                security_info["potential_vulnerabilities"].append(
                    f"Potentially dangerous HTTP methods allowed: {allowed_methods}"
                )

    def _analyze_html_content(self, security_info, content, url):
        try:
            soup = BeautifulSoup(content, 'html.parser')
            self._check_html_comments(security_info, soup)
            self._check_script_paths(security_info, soup)
            self._check_meta_tags(security_info, soup)
            self._check_specific_patterns(security_info, content)
        except Exception as e:
            ColorPrint.error(f"Error parsing HTML at {url}: {str(e)}")

    def _check_html_comments(self, security_info, soup):
        comments = soup.find_all(string=lambda text: isinstance(text, Comment))
        for comment in comments:
            comment_text = comment.strip().lower()
            if re.search(r'version|v\d+|\d+\.\d+\.\d+', comment_text):
                security_info["interesting_findings"].append(
                    f"Version information in HTML comment: {comment.strip()}"
                )
            for tech, patterns in self.tech_fingerprints.items():
                for pattern in patterns:
                    if pattern.search(comment_text):
                        security_info["technologies"].append(f"{tech} (Comment)")

    def _check_script_paths(self, security_info, soup):
        scripts = soup.find_all('script', src=True)
        sensitive_keywords = ['internal', 'admin']
        for script in scripts:
            src = script['src']
            if any(keyword in src for keyword in sensitive_keywords):
                security_info["interesting_findings"].append(
                    f"Potentially sensitive script path: {src}"
                )
            for tech, patterns in self.tech_fingerprints.items():
                for pattern in patterns:
                    if pattern.search(src):
                        security_info["technologies"].append(f"{tech} (Script Path)")

    def _check_meta_tags(self, security_info, soup):
        meta_generator = soup.find('meta', attrs={'name': 'generator'})
        if meta_generator:
            generator_content = meta_generator['content']
            security_info["technologies"].append(f"Meta Generator: {generator_content}")
            for tech, patterns in self.tech_fingerprints.items():
                for pattern in patterns:
                    if pattern.search(generator_content):
                        security_info["technologies"].append(f"{tech} (Meta Generator)")
        # Add more meta tag checks here
        meta_framework = soup.find('meta', attrs={'name': 'framework'})
        if meta_framework and meta_framework['content']:
            security_info["technologies"].append(f"Meta Framework: {meta_framework['content']}")

    def _check_specific_patterns(self, security_info, content):
        for tech, patterns in self.tech_fingerprints.items():
            for pattern in patterns:
                if pattern.search(content):
                    security_info["technologies"].append(f"{tech} (Content Pattern)")

    def _analyze_favicon(self, security_info, url):
        try:
            favicon_url = f"{url.split('//')[0]}//{url.split('//')[1].split('/')[0]}/favicon.ico"
            response = requests.get(favicon_url, timeout=5)
            if response.status_code == 200 and 'image' in response.headers.get('Content-Type', ''):
                # Use SHA-256 for more robust hashing
                favicon_hash = hashlib.sha256(response.content).hexdigest()
                if favicon_hash in self.favicon_hashes:
                    security_info["technologies"].append(f"{self.favicon_hashes[favicon_hash]} (Favicon)")
                else:
                    # Consider also storing a base64 encoded version if needed
                    readable_hash = base64.b64encode(hashlib.sha256(response.content).digest()).decode('utf-8')
                    if readable_hash in self.favicon_hashes:
                        security_info["technologies"].append(f"{self.favicon_hashes[readable_hash]} (Favicon)")

        except requests.RequestException:
            pass # Ignore favicon errors

    def _determine_primary_technology(self, tech_details):
        detected_tech = set()
        if "SecurityScan" in tech_details and tech_details["SecurityScan"].get("technologies"):
            for tech_string in tech_details["SecurityScan"]['technologies']:
                # Extract technology name before any colon or parentheses
                tech_name = re.split(r'[:(]', tech_string)[0].strip().lower()
                detected_tech.add(tech_name)

        if "WhatWeb" in tech_details and tech_details["WhatWeb"]:
            for line in tech_details["WhatWeb"].splitlines():
                parts = line.split('[')
                if len(parts) > 0:
                    detected_tech.add(parts[0].strip().lower())

        if "Wappalyzer" in tech_details and tech_details["Wappalyzer"]:
            for line in tech_details["Wappalyzer"].splitlines():
                detected_tech.add(line.strip().lower())

        # Prioritize specific technologies
        prioritized_tech = ["wordpress", "joomla", "drupal", "magento", "next.js", "react", "angular", "vue.js", "php", "asp.net", "nodejs", "ruby"]
        for tech in prioritized_tech:
            if tech in detected_tech:
                return tech

        if "iis" in detected_tech:
            return "asp" # If IIS is detected but not ASP.NET

        return "general"