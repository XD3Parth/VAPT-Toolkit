import aiohttp
import asyncio
import csv
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
import time
from datetime import datetime

class FastWebCrawler:
    def __init__(self, base_url, max_depth, output_file="crawl_output.csv", max_connections=100):
        self.base_url = base_url
        self.max_depth = max_depth
        self.visited = set()
        self.to_visit = set([base_url])
        self.output_file = output_file
        self.session = None
        self.max_connections = max_connections
        self.found_files = set()  # Store files found during the crawl

        self.common_paths = [
            '/admin', '/logout', '/login', '/dashboard', '/admin.php', '/login.php', '/logout.php', '/dashboard.php',
            '/admin-panel', '/admin-login', '/admin-dashboard', '/user', '/users', '/profile', '/settings', '/account',
            '/user/profile', '/admin/settings', '/admin/login', '/admin/logout', '/admin/dashboard', '/loginform',
            '/loginpanel', '/admin-console', '/user-dashboard', '/user-login', '/signup', '/signup.php', 
            '/register', '/register.php', '/settings.php', '/user-settings', '/admin-settings', '/admin-login.php', 
            '/admin-dashboard.php', '/admin/console', '/admin-interface', '/admin-control-panel', 
            '/manage-users', '/manage-content', '/cms', '/control-panel', '/admin-dashboard.php', '/admin-portal', 
            '/cms.php', '/dashboard-admin', '/cms-admin', '/settings-admin', '/admin-portal.php', '/manage-users.php', 
            '/edit-profile', '/change-password', '/logout-user', '/session-logout', '/users-list', '/admin/api',
            '/admin-settings.php', '/admin-panel.php', '/panel.php', '/user-dashboard.php', '/adminapi', '/admin/api.php', 
            '/admin-management', '/adminconsole', '/settings-user', '/adminsite', '/admin/setting', '/adminfiles', 
            '/admin-console-form', '/admin-service', '/admin-area/', '/admincontent', '/adminfiles.php', '/cms-login',
            '/webadmin', '/adminpages', '/backup', '/settings-panel', '/admin-test', '/admin-area-dashboard', 
            '/users-area', '/admin-config.php', '/manage-profile', '/site-config', '/app-admin', '/adminedit', 
            '/admin-login-check', '/web-admin.php', '/admin-system', '/admin-edit.php', '/site-admin', '/usersettings', 
            '/userprofile', '/admin-page', '/manager', '/admin-actions', '/adminstatus', '/control-dashboard', 
            '/control-panel.php', '/admin-register', '/admin-access', '/web-admin-login', '/admin-info', '/admin-login-check'
        ]
        
        # Open the CSV file and write the headers
        self.file = open(self.output_file, "w", newline='', encoding="utf-8")
        self.csv_writer = csv.writer(self.file)
        self.csv_writer.writerow(["Timestamp", "URL", "Type", "Status", "Depth"])  # Header row

    async def get_html(self, url):
        """Fetches the HTML content of a URL using aiohttp."""
        try:
            async with self.session.get(url) as response:
                if response.status == 200:
                    return await response.text(), response.status
                else:
                    return None, response.status
        except Exception as e:
            print(f"Error fetching {url}: {e}")
            return None, None

    def extract_links(self, html, url):
        """Extracts all the links from the HTML content."""
        soup = BeautifulSoup(html, 'html.parser')
        links = set()
        for anchor in soup.find_all('a', href=True):
            link = anchor['href']
            link = urljoin(url, link)  # Handle relative links
            links.add(link)
        return links

    def extract_files(self, html, url):
        """Extract all file paths like images, CSS, JavaScript, etc. from the page."""
        soup = BeautifulSoup(html, 'html.parser')
        files = set()

        # Find all file references such as images, CSS, and JS
        for tag in soup.find_all(['img', 'script', 'link'], src=True):
            src = tag.get('src') or tag.get('href')  # Handle src for img, js and href for css
            file_url = urljoin(url, src)  # Resolve relative URLs
            if any(file_url.endswith(ext) for ext in ['.js', '.css', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.json']):
                files.add(file_url)

        return files

    async def check_common_paths(self, url):
        """Explicitly check common paths like /admin, /login, /logout, /dashboard for every visited page."""
        tasks = []
        for path in self.common_paths:
            common_url = urljoin(url, path)  # Combine base URL with common path
            if common_url not in self.visited:
                self.visited.add(common_url)
                tasks.append(self.session.get(common_url))

        # Use asyncio.gather to make the requests concurrently
        responses = await asyncio.gather(*tasks)

        for response, common_url in zip(responses, self.common_paths):
            status = response.status
            status_text = "OK" if status == 200 else f"Not Found (Status code: {status})"
            if status == 200:
                print(f"Found common path: {common_url}")
                self.log_to_csv(common_url, "Common Path", status_text)  # Log the found common path
            else:
                print(f"Common path not found: {common_url} (Status code: {status})")
                self.log_to_csv(common_url, "Common Path", status_text)

    async def crawl(self, url, depth):
        """Crawl the website and extract all links, with depth control."""
        if depth > self.max_depth:
            return

        # Check common paths on every page
        await self.check_common_paths(url)

        html, status = await self.get_html(url)
        if html is None:
            return

        links = self.extract_links(html, url)
        files = self.extract_files(html, url)  # Extract files from the page

        # Log found files (images, JS, CSS)
        for file in files:
            if file not in self.found_files:
                self.found_files.add(file)
                print(f"Found file: {file}")
                self.log_to_csv(file, "File", "Found")  # Log the file path

        print(f"Crawling {url} (depth {depth}) - Found {len(links)} links and {len(files)} files")
        self.log_to_csv(url, "Link", f"Found {len(links)} links and {len(files)} files", depth)

        tasks = []
        for link in links:
            if link not in self.visited:
                self.visited.add(link)
                tasks.append(self.crawl(link, depth + 1))  # Add the next crawl to the task list

        # Run all crawls concurrently with limits on maximum connections
        await asyncio.gather(*tasks)

    def log_to_csv(self, url, url_type, status_text, depth=None):
        """Log the given URL or file to the CSV output."""
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if depth is None:
            depth = "N/A"
        self.csv_writer.writerow([current_time, url, url_type, status_text, depth])

    def close_file(self):
        """Close the CSV file after the crawl is finished."""
        self.file.close()

    async def get_user_input(self):
        """Prompts the user for input to customize the crawler's behavior."""
        print("Web Crawler Configuration:")
        base_url = input("Enter the base URL to start crawling (e.g., http://example.com): ")
        max_depth = int(input("Enter the maximum depth of crawl (e.g., 2): "))
        
        return base_url, max_depth

    async def start_crawl(self):
        """Start the crawling process using asyncio and aiohttp."""
        base_url, max_depth = await self.get_user_input()
        print(f"Starting crawl for: {base_url}")

        # Create aiohttp session for concurrent HTTP requests with limited connections
        conn = aiohttp.TCPConnector(limit_per_host=self.max_connections)
        async with aiohttp.ClientSession(connector=conn) as session:
            self.session = session
            await self.crawl(base_url, 0)

# Main Execution
if __name__ == "__main__":
    crawler = FastWebCrawler("http://example.com", 2)  # Default URL, will be replaced with user input
    asyncio.run(crawler.start_crawl())

    # Close the CSV file after crawling
    crawler.close_file()
