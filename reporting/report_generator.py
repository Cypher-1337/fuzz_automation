# reporting/report_generator.py
import os
import json
from datetime import datetime
from utils.color_print import ColorPrint
import requests
import re

class ReportGenerator:
    def __init__(self, output_dir):
        self.output_dir = output_dir

    def generate_report(self, subdomain, results):
        """Generate an HTML report for the scan results."""
        # Sanitize subdomain for filename
        safe_subdomain = subdomain.replace("://", "_").replace(".", "_").replace("/", "_")
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        report_file = os.path.join(self.output_dir, f"report_{safe_subdomain}_.html")

        os.makedirs(self.output_dir, exist_ok=True)

        try:
            with open(report_file, 'w') as file:
                file.write(self._generate_html_content(subdomain, results, timestamp))
            ColorPrint.success(f"Report generated: {report_file}")
        except Exception as e:
            ColorPrint.error(f"Error generating report: {str(e)}")

    def _categorize_urls(self, fuzz_results):
        """Categorize URLs based on patterns"""
        categories = {
            'Admin': [],
            'API': [],
            'Assets': [],
            'Auth': [],
            'Config': [],
            'Content': [],
            'Core': [],
            'Data': [],
            'Docs': [],
            'System': [],
            'User': [],
            'Dev': [],
            'Backup': [],
            'Misc': []
        }

        patterns = {
            'Admin': [
                '/admin', '/manage', '/dashboard', '/control', '/administrator', '/login', '/sysadmin', '/backend',
                '/admin/', '/manage/', '/dashboard/', '/control/', '/administrator/', '/login/', '/sysadmin/', '/backend/',
                '/wp-admin', '/wp-login.php', '/cpanel', '/webmail', '/phpmyadmin',
                r'/admin\d+', r'/manage\d+', r'/control\d+' # Regex for admin/manage/control followed by numbers
            ],
            'API': [
                '/api/', '/rest/', '/graphql', '/endpoint', '/v[0-9]+/', '\\.json$', '\\.xml$',
                '/api/v[0-9]+/', '/v[0-9]+/api/',
                r'/api/\w+/\w+',  # Example: /api/users/123
                r'/v\d+/\w+/\d+'  # Example: /v1/products/456
            ],
            'Assets': [
                '/images/', '/css/', '/js/', '/static/', '/media/', '/assets/', '\\.(png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|otf)$',
                '\\.bmp$', '\\.webp$', '\\.mp4$', '\\.avi$', '\\.mov$', '\\.mp3$', '\\.ogg$', '\\.wav$',
                '/fonts/', '/img/'
            ],
            'Auth': [
                '/login', '/auth/', '/oauth', '/signin', '/signup', '/register', '/logout', '/password',
                '/log-in', '/sign-in', '/sign-up', '/forgot-password', '/reset-password',
                '/auth/login', '/auth/register', '/account/login', '/account/register',
                '\\.aspx$', '\\.php$', '\\.jsp$' # Potential auth pages in different technologies
            ],
            'Config': [
                '/config', '/settings', '/setup', '/env', '\\.conf$', '\\.ini$', '\\.yaml$', '\\.yml$',
                '\\.toml$', '\\.properties$', '/.env', '/.env.example', '/config.php', '/configuration.ini',
                '/application.yml', '/appsettings.json'
            ],
            'Content': [
                '/content/', '/posts/', '/articles/', '/pages/', '/blog/',
                '/news/', '/updates/', '/downloads/', '/public/',
                r'/\d{4}/\d{2}/\d{2}/' # Year/Month/Day pattern in URLs
            ],
            'Core': [
                '/core/', '/main/', '/base/', '/foundation/',
                '/includes/', '/libs/', '/src/', '/app/'
            ],
            'Data': [
                '/data/', '/database/', '/storage/', '/cache/', '/dump', '\\.sql$',
                '\\.csv$', '\\.xls$', '\\.xlsx$', '\\.backup$', '\\.bak$',
                '/db/', '/sql/'
            ],
            'Docs': [
                '/docs/', '/documentation/', '/help/', '/manual/', '/readme', '\\.pdf$', '\\.txt$',
                '\\.md$', '/swagger', '/api-docs', '/redoc', '/openapi',
                'CHANGELOG', 'LICENSE', 'COPYING'
            ],
            'System': [
                '/system/', '/server/', '/service/', '/process/', '/status', '/health',
                '/info', '/version', '/healthcheck', '/server-status',
                '\\.log$'
            ],
            'User': [
                '/user/', '/profile/', '/account/', '/member/',
                '/users/', '/profiles/', '/accounts/', '/members/',
                '/my-account', '/myprofile'
            ],
            'Dev': [
                '/dev/', '/debug/', '/test/', '/staging/', '/playground/',
                '\\.git/', '\\.svn/', '\\.docker/', '\\.vscode/',
                'phpinfo\\.php'
            ],
            'Backup': [
                '\\.backup$', '\\.bak$', '\\.~$', '\\.old$', '\\.orig$',
                '/backup/', '/backups/'
            ],
            'Misc': [
                '\\.php~', '\\.swp', '\\.swo', '\\.inc', '\\.tpl',
                '/sitemap\\.xml', '/robots\\.txt', '/crossdomain\\.xml', '/favicon\\.ico'
            ]
        }

        for item in fuzz_results:
            url = item.get('url')
            redirect_url = self._get_redirect_url(url)
            url_data = {'url': url, 'status': item.get('status'), 'length': item.get('length'), 'redirect_url': redirect_url}
            categorized = False

            for category, keywords in patterns.items():
                if any(keyword in url.lower() for keyword in keywords):
                    categories[category].append(url_data)
                    categorized = True
                    break

            if not categorized:
                categories['Misc'].append(url_data)

        return categories

    def _get_redirect_url(self, url):
        try:
            response = requests.get(url, allow_redirects=False, timeout=5)
            if 300 <= response.status_code < 400 and 'Location' in response.headers:
                return response.headers['Location']
        except requests.RequestException:
            return None
        return None

    def _generate_html_content(self, subdomain, results, timestamp):
        """Generate the HTML content for the report in dark mode."""
        html = []
        html.append("<!DOCTYPE html>")
        html.append("<html lang='en' class='dark-mode'>")
        html.append("<head>")
        html.append("<meta charset='UTF-8'>")
        html.append("<meta name='viewport' content='width=device-width, initial-scale=1.0'>")
        html.append("<title>Web Scanner Report</title>")
        html.append("<link rel='preconnect' href='https://fonts.googleapis.com'>")
        html.append("<link rel='preconnect' href='https://fonts.gstatic.com' crossorigin>")
        html.append("<link href='https://fonts.googleapis.com/css2?family=Roboto:wght@400;500;700&display=swap' rel='stylesheet'>")
        html.append("<link href='https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css' rel='stylesheet' />")
        html.append(self._get_css_styles())
        html.append(self._get_javascript())
        html.append("</head>")
        html.append("<body>")
        html.append("<div class='container'>")
        html.append("<header class='report-header'>")
        html.append("<div class='header-content'>")
        html.append("<h1 class='report-title'><i class='fas fa-spider'></i> Web Scanner Report</h1>")
        html.append(f"<p class='report-timestamp'>Generated on: {timestamp}</p>")
        html.append(f"<p class='report-target'>Target Subdomain: {subdomain}</p>")
        if subdomain in results and 'technology' in results[subdomain]:
            html.append(f"<p class='report-technology'>Detected Technology: {results[subdomain]['technology']}</p>")
        html.append("</div>")
        html.append("</header>")

        # Add quick navigation
        html.append("<nav class='quick-nav'>")
        html.append("<div class='search-box'>")
        html.append("<i class='fas fa-search'></i> <input type='text' id='urlSearch' placeholder='Search URLs...' />")
        html.append("</div>")
        html.append("<div class='category-filters'>")
        html.append("<button class='category-button active' data-category='all'>All</button>")
        html.append("<button class='category-button' data-category='admin'>Admin</button>")
        html.append("<button class='category-button' data-category='api'>API</button>")
        html.append("<button class='category-button' data-category='auth'>Auth</button>")
        html.append("<button class='category-button' data-category='content'>Content</button>")
        html.append("<button class='category-button' data-category='system'>System</button>")
        html.append("<button class='category-button' data-category='other'>Other</button>")
        html.append("</div>")
        html.append("</nav>")

        # Add summary section
        html.append(self._generate_summary_section(subdomain, results))

        # Add sorting controls
        html.append("<div class='sorting-controls'>")
        html.append("<label for='sort-by'>Sort By:</label>")
        html.append("<select id='sort-by'>")
        html.append("<option value=''>-- Select --</option>")
        html.append("<option value='status-asc' selected>Status Asc</option>")  # Set default to status-asc
        html.append("<option value='status-desc'>Status Desc</option>")
        html.append("<option value='size-asc'>Size Asc</option>")
        html.append("<option value='size-desc'>Size Desc</option>")
        html.append("</select>")
        html.append("</div>")

        # Add detailed results with categories
        html.append(self._generate_detailed_results(results))

        html.append("</div>")
        html.append("</body>")
        html.append("</html>")

        return "\n".join(html)

    def _get_javascript(self):
        """Return JavaScript for interactivity"""
        return """
        <script>
        document.addEventListener('DOMContentLoaded', function() {
            const searchInput = document.getElementById('urlSearch');
            const getUrlItems = () => document.querySelectorAll('.url-item');

            searchInput.addEventListener('input', function(e) {
                const searchTerm = e.target.value.toLowerCase();
                getUrlItems().forEach(item => {
                    const url = item.querySelector('.url a').textContent.toLowerCase();
                    item.style.display = url.includes(searchTerm) ? 'flex' : 'none';
                });
            });

            const categoryButtons = document.querySelectorAll('.category-filters .category-button');
            const resultSections = document.querySelectorAll('.category-section');

            categoryButtons.forEach(button => {
                button.addEventListener('click', function() {
                    const category = this.dataset.category;

                    categoryButtons.forEach(btn => btn.classList.remove('active'));
                    this.classList.add('active');

                    resultSections.forEach(section => {
                        section.style.display = (category === 'all' || section.dataset.category === category) ? 'block' : 'none';
                    });
                });
            });

            const sortBySelect = document.getElementById('sort-by');
            sortBySelect.addEventListener('change', function() {
                const sortType = this.value;
                sortResults(sortType);
            });

            // Initial sorting on page load
            sortResults('status-asc');

            function sortResults(sortType) {
                const categorySections = document.querySelectorAll('.category-section');
                categorySections.forEach(section => {
                    const items = Array.from(section.querySelectorAll('.url-item'));
                    items.sort((a, b) => {
                        let valA, valB;
                        if (sortType.startsWith('status')) {
                            valA = parseInt(a.querySelector('.status').textContent);
                            valB = parseInt(b.querySelector('.status').textContent);
                        } else if (sortType.startsWith('size')) {
                            valA = parseInt(a.querySelector('.size').dataset.bytes);
                            valB = parseInt(b.querySelector('.size').dataset.bytes);
                        }

                        if (sortType.endsWith('asc')) {
                            return valA - valB;
                        } else {
                            return valB - valA;
                        }
                    });
                    items.forEach(item => section.appendChild(item));
                });
            }
        });
        </script>
        """

    def _get_css_styles(self):
        """Return enhanced CSS styles with larger container and fonts, and color-coded status."""
        return """
        <style>
            /* Futuristic Color Palette */
            :root {
                --bg-color: #0B0D17;
                --text-color: #E0E0E0;
                --primary-color: #6FFFB0;
                --secondary-color: #A3D9FF;
                --accent-color: #FF90E8;
                --success-color: #00FF7F;
                --danger-color: #FF4F4F;
                --warning-color: #FFD700;
                --info-color: #00BFFF;
                --border-color: #2E3440;
                --highlight-color: var(--primary-color);
                --code-bg: #1E232A;
            }

            body {
                font-family: 'Roboto', sans-serif;
                margin: 0;
                font-size: 1.1rem;
                background-color: var(--bg-color);
                color: var(--text-color);
                transition: background-color 0.3s, color 0.3s;
            }

            .container {
                width: 90%;
                max-width: 1600px;
                margin: 20px auto;
                padding: 40px;
                border-radius: 12px;
                background-color: #1A1E27;
                box-shadow: 0 0 20px rgba(var(--primary-color-rgb, 111, 255, 176), 0.2);
                transition: background-color 0.3s, box-shadow 0.3s;
            }

            .report-header {
                text-align: center;
                margin-bottom: 50px;
                padding: 30px 0;
                border-bottom: 2px solid var(--border-color);
                transition: border-bottom-color 0.3s;
            }

            .report-title {
                font-size: 2.8em;
                margin-bottom: 15px;
                color: var(--primary-color);
                text-shadow: 0 0 10px rgba(var(--primary-color-rgb, 111, 255, 176), 0.8);
            }

            .report-title i {
                margin-right: 15px;
            }

            .report-timestamp {
                font-size: 1.2em;
                color: var(--secondary-color);
            }

            .report-target {
                font-size: 1.2em;
                color: var(--info-color);
            }

            .report-technology {
                font-size: 1.2em;
                color: var(--accent-color);
            }

            .quick-nav {
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 40px;
                padding: 20px 30px;
                border-radius: 8px;
                border: 1px solid var(--border-color);
                background-color: var(--code-bg);
                transition: background-color 0.3s, border-color 0.3s;
            }

            .search-box {
                display: flex;
                align-items: center;
                border: 1px solid var(--border-color);
                border-radius: 6px;
                padding-left: 15px;
                background-color: #2C313A;
                transition: background-color 0.3s, border-color 0.3s;
            }

            .search-box i {
                margin-right: 10px;
                color: var(--secondary-color);
            }

            .search-box input {
                border: none;
                padding: 12px;
                font-size: 1.1rem;
                flex-grow: 1;
                outline: none;
                background-color: transparent;
                color: var(--text-color);
            }

            .category-filters {
                display: flex;
                gap: 15px;
                flex-wrap: wrap;
                justify-content: center;
            }

            .category-button {
                padding: 12px 25px;
                border: 1px solid var(--accent-color);
                border-radius: 25px;
                background-color: transparent;
                color: var(--accent-color);
                cursor: pointer;
                font-size: 1rem;
                transition: background-color 0.3s, color 0.3s, border-color 0.3s;
            }

            .category-button.active {
                background-color: var(--accent-color);
                color: var(--bg-color);
                border-color: var(--accent-color);
            }

            .summary {
                padding: 30px;
                margin-bottom: 40px;
                border-left: 5px solid var(--highlight-color);
                background-color: var(--code-bg);
                border-radius: 8px;
                transition: background-color 0.3s, border-color 0.3s;
            }

            .summary h2 {
                margin-top: 0;
                margin-bottom: 30px; /* Increased margin */
                font-size: 2rem; /* Increased font size */
                color: var(--primary-color);
                text-align: center; /* Center the title */
            }

            .stats-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
                gap: 30px;
            }

            .stat-card {
                padding: 30px; /* Increased padding */
                border-radius: 10px; /* Slightly more rounded */
                border: 1px solid var(--border-color);
                text-align: center;
                background-color: #2C313A;
                color: var(--text-color);
                transition: background-color 0.3s, border-color 0.3s;
            }

            .stat-card .stat-title {
                margin-top: 0;
                font-size: 1.6rem; /* Increased font size */
                color: var(--primary-color);
            }

            .stat-card .stat-value {
                font-size: 2.2rem; /* Prominent value */
                font-weight: bold;
                margin-bottom: 0;
            }

            .status-bar-with-progress {
                display: flex;
                align-items: center;
                margin-bottom: 15px;
            }

            .status-label {
                flex-basis: 20%;
                font-weight: bold;
            }

            .progress-bar {
                flex-grow: 1;
                height: 10px;
                background-color: #444954;
                border-radius: 5px;
                margin-right: 15px;
                overflow: hidden;
            }

            .progress-bar-inner {
                height: 100%;
                border-radius: 5px;
                transition: width 0.4s ease-in-out;
            }

            .progress-bar-inner.success {
                background-color: var(--success-color);
            }

            .progress-bar-inner.info {
                background-color: var(--info-color);
            }

            .progress-bar-inner.danger {
                background-color: var(--danger-color);
            }

            .progress-bar-inner.warning {
                background-color: var(--warning-color);
            }

            .status-count {
                flex-basis: 10%;
                text-align: right;
            }

            /* New status count colors for summary */
            .status-count.success {
                color: var(--success-color);
            }
            .status-count.info {
                color: var(--info-color);
            }
            .status-count.danger {
                color: var(--danger-color);
            }
            .status-count.warning {
                color: var(--warning-color);
            }

            .detailed-results {
                margin-top: 50px;
            }

            .detailed-results h2 {
                margin-bottom: 30px;
                font-size: 1.7rem;
                color: var(--primary-color);
            }

            .category-section {
                margin-bottom: 30px;
                padding: 25px;
                border-radius: 10px;
                border-left: 5px solid var(--highlight-color);
                background-color: var(--code-bg);
                transition: background-color 0.3s, border-color 0.3s;
            }

            .category-section h3 {
                margin-top: 0;
                margin-bottom: 20px;
                font-size: 1.5rem;
                border-bottom: 1px dashed var(--accent-color);
                padding-bottom: 15px;
                color: var(--accent-color);
                transition: color 0.3s, border-bottom-color 0.3s;
            }

            .url-item {
                display: flex;
                justify-content: space-between;
                align-items: center;
                padding: 15px 25px;
                margin-bottom: 12px;
                border-radius: 6px;
                border: 1px solid var(--border-color);
                font-size: 1.1rem;
                background-color: #2C313A;
                color: var(--text-color);
                transition: background-color 0.3s, border-color 0.3s;
            }

            .url-item:nth-child(even) {
                background-color: #353A43;
            }

            .url-item .url {
                flex-grow: 1;
                margin-right: 15px;
                word-break: break-all;
            }

            .url-item .url a {
                text-decoration: none;
                color: var(--info-color);
                transition: color 0.3s;
            }

            .url-item .status {
                padding: 8px 15px;
                border-radius: 4px;
                font-size: 1rem;
                color: var(--bg-color);
            }

            .url-item .status-200 { background-color: var(--success-color); }
            .url-item .status-301, .url-item .status-302, .url-item .status-307 { background-color: var(--warning-color); color: #000; }
            .url-item .status-400, .url-item .status-401, .url-item .status-403, .url-item .status-404 { background-color: var(--danger-color); }
            .url-item .status-500 { background-color: var(--secondary-color); }

            .url-item .redirect {
                font-size: 0.9rem;
                color: var(--warning-color);
                margin-left: 10px;
            }

            .sorting-controls {
                margin-bottom: 40px;
                text-align: right;
            }

            .sorting-controls label {
                margin-right: 10px;
                font-size: 1.1rem;
                color: var(--text-color);
                transition: color 0.3s;
            }

            .sorting-controls select {
                padding: 12px;
                border-radius: 6px;
                border: 1px solid var(--border-color);
                font-size: 1.1rem;
                outline: none;
                background-color: #2C313A;
                color: var(--text-color);
                transition: background-color 0.3s, color 0.3s, border-color 0.3s;
            }

            /* Responsive adjustments */
            @media (max-width: 768px) {
                .container {
                    padding: 30px;
                }

                .quick-nav {
                    flex-direction: column;
                    align-items: stretch;
                }

                .search-box {
                    margin-bottom: 15px;
                }

                .category-filters {
                    justify-content: space-around;
                }

                .category-button {
                    flex-grow: 0;
                    width: auto;
                }

                .stats-grid {
                    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
                }
            }
        </style>
        """

    def _generate_summary_section(self, subdomain, results):
        """Generate an enhanced summary section with statistics and color-coded status."""
        total_urls = 0
        status_codes = {}

        for sub, data in results.items():
            if 'fuzz_results' in data and data['fuzz_results']:
                for item in data['fuzz_results']['results']:
                    total_urls += 1
                    status = item.get('status', 'unknown')
                    status_codes[status] = status_codes.get(status, 0) + 1

        html = ["<div class='summary'>"]
        html.append("<h2>Scan Summary</h2>")

        # Statistics grid
        html.append("<div class='stats-grid'>")
        html.append(f"<div class='stat-card'><h3 class='stat-title'>Total URLs</h3><p class='stat-value'>{total_urls}</p></div>")

        # Status code distribution with progress bars
        html.append("<div class='stat-card'>")
        html.append("<h3 class='stat-title'>Status Codes</h3>")
        for status, count in sorted(status_codes.items()):
            percentage = (count / total_urls) * 100 if total_urls > 0 else 0
            status_color_class = ''
            status_count_class = ''
            if 200 <= status < 300:
                status_color_class = 'success'
                status_count_class = 'success'
            elif 300 <= status < 400:
                status_color_class = 'info'
                status_count_class = 'info'
            elif 400 <= status < 600:
                status_color_class = 'danger'
                status_count_class = 'danger'

            html.append(f"""
                <div class='status-bar-with-progress'>
                    <span class='status-label'>{status}</span>
                    <div class='progress-bar'>
                        <div class='progress-bar-inner {status_color_class}' style='width: {percentage:.1f}%'></div>
                    </div>
                    <span class='status-count {status_count_class}'>{count}</span>
                </div>
            """)
        html.append("</div>")

        html.append("</div>")
        html.append("</div>")

        return "\n".join(html)

    def _format_bytes(self, size_in_bytes):
        """Convert bytes to human-readable format (KB, MB)."""
        if size_in_bytes >= 1024 * 1024:
            return f"{size_in_bytes / (1024 * 1024):.2f} MB"
        elif size_in_bytes >= 1024:
            return f"{size_in_bytes / 1024:.2f} KB"
        elif size_in_bytes is not None:
            return f"{size_in_bytes} bytes"
        else:
            return "N/A"

    def _generate_detailed_results(self, results):
        """Generate detailed results with categorized URLs and human-readable sizes."""
        html = ["<div class='detailed-results'>"]
        html.append("<h2>Detailed Results</h2>")

        for subdomain, data in results.items():
            if 'fuzz_results' in data and data['fuzz_results']:
                categorized_results = self._categorize_urls(data['fuzz_results']['results'])

                for category, urls in sorted(categorized_results.items()):
                    if urls:  # Only show categories with results
                        html.append(f"<div class='category-section' data-category='{category.lower()}'>")
                        html.append(f"<h3>{category}</h3>")

                        # Sort URLs by status code in ascending order by default
                        for url_data in sorted(urls, key=lambda x: x.get('status', float('inf'))):
                            status_class = f"status-{url_data.get('status', 'unknown')}"
                            size_bytes = url_data.get('length')
                            formatted_size = self._format_bytes(size_bytes)
                            redirect_info = f"<span class='redirect'>↪ {url_data['redirect_url']}</span>" if url_data.get('redirect_url') else ""
                            html.append(f"""
                                <div class='url-item'>
                                    <span class='url'><a href='{url_data['url']}' target='_blank'>{url_data['url']}</a></span>
                                    <span class='status {status_class}'>{url_data.get('status', 'Unknown')}</span>
                                    <span class='size' data-bytes='{size_bytes}'>{formatted_size}</span>
                                    {redirect_info}
                                </div>
                            """)

                        html.append("</div>")
            else:
                html.append("<p>No fuzzing results found for this subdomain.</p>")

        html.append("</div>")
        return "\n".join(html)