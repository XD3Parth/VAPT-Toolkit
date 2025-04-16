# Web Crawler for Web Security Testing

Welcome to the **Web Crawler for Web Security Testing** repository! This project is a **multi-threaded web crawler** designed to help identify hidden paths, files, and potential vulnerabilities within websites. Built with security assessments in mind, this crawler can help penetration testers, bug hunters, and security enthusiasts find exposed endpoints like `/admin`, `/login`, and `/dashboard`.

As a **cybersecurity fresher** and ethical hacking enthusiast, I created this tool to assist in **web application security** audits, vulnerability discovery, and penetration testing.

## 🚀 Features

- **Crawl Website Paths**: Automatically crawls common paths like `/admin`, `/login`, `/logout`, `/dashboard`, and more.
- **Multi-threading**: Utilizes threading to speed up the crawling process and improve efficiency.
- **Path Discovery**: Scans for hidden directories and files using a list of common paths (e.g., `/config`, `/upload`, `/admin.php`).
- **Customizable Depth**: Allows users to set crawl depth to explore deeper into the website’s structure.
- **Automated Vulnerability Scanning**: Detects common vulnerable paths that could be exposed.
- **CSV Report**: Saves results in a well-structured **CSV file** for easier readability and tracking.
- **Organized Logs**: Saves detailed logs of found paths, response codes, and server status.

## 🛠️ Technologies & Tools Used

- **Programming Language**: Python
- **Libraries**: 
  - `requests`
  - `aiohttp` (for asynchronous requests)
  - `BeautifulSoup`
  - `threading` (for multi-threading)
  - `csv` (for storing results)
- **OS**: Cross-platform (Linux, Windows, macOS)

## 💻 How It Works

1. **User Input**: The user is prompted to enter the website URL and desired crawl depth.
2. **Crawl Common Paths**: The crawler attempts to find common paths on the website (like `/admin`, `/login`, `/dashboard`).
3. **Multi-Threading**: Multiple threads are used to ensure fast and efficient crawling of paths.
4. **Log Results**: The results, including status codes and response data, are saved into a CSV file for review.
5. **CSV Report**: The crawler generates a structured **CSV report** with details like the URL, response code, and status.

## 🔑 Key Features

- **Fast Crawling with Threading**: Improve the speed of path crawling by using threads.
- **Web Application Security Focus**: Designed to look for common entry points and sensitive areas like `/admin` and `/config`.
- **Common Path Discovery**: The crawler checks for over 100 common paths and files.
- **Report Generation**: Automatically saves a CSV file for organized results.

## 📥 Installation

1. Clone this repository:
   ```bash
   git clone https://github.com/ParthXD7/Web-Security-Crawler.git
   cd Web-Security-Crawler
