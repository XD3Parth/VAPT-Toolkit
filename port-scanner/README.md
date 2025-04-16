# Advanced Port Scanner

## Project Overview
This **Advanced Port Scanner** is a Python-based tool designed to efficiently scan multiple ports on a target machine. It leverages multithreading for faster performance and logs the scan results into a timestamped report file.

## Developer
This project is created by **ParthXD7**, a cybersecurity intern with a passion for developing tools that enhance network security and vulnerability assessment.

## Features
- **Fast Multithreaded Scanning**: Simultaneous port scanning using multiple threads and batch processing.
- **Customizable Parameters**: Supports custom port ranges, thread counts, and timeout settings.
- **Service Detection**: Identifies the service running on open ports.
- **Real-Time Updates**: Displays scanning progress, estimated time remaining, and results in real-time.
- **Report Generation**: Saves a detailed scan report in a `.txt` file for further analysis.

## How It Works
1. The program accepts the target (IP or hostname), port range, timeout, thread count, and batch size from the user.
2. It resolves the hostname to its corresponding IP address.
3. The ports are divided into batches and scanned concurrently using multiple threads.
4. Results for open ports, including detected services, are displayed on the console and saved to a file.

## Installation
1. **Clone the repository**:
   ```bash
   git clone https://github.com/ParthXD7/Advanced-Port-Scanner.git
   cd Advanced-Port-Scanner
   ```
2. **Install Python dependencies**:
   This program uses Python's standard library, so no additional dependencies are required.
3. **Run the scanner**:
   ```bash
   python advanced_port_scanner.py
   ```

## Input Parameters
1. **Target**: The target IP or hostname (e.g., `192.168.1.1` or `example.com`).
2. **Start Port**: The first port in the range to scan (e.g., `20`).
3. **End Port**: The last port in the range to scan (e.g., `100`).
4. **Timeout**: Time in seconds to wait for a response from a port (e.g., `1.0`).
5. **Threads**: Number of threads for concurrent scanning (e.g., `4`).
6. **Batch Size**: Number of ports to scan simultaneously in each thread (e.g., `5`).

## Example
Input:
```
Enter target IP or hostname: 192.168.1.1
Enter start port (0-65535): 20
Enter end port (0-65535): 100
Enter timeout (seconds): 1.0
Enter number of threads: 4
Enter number of ports to scan simultaneously (batch size): 5
```

Output:
```
Starting port scan on 192.168.1.1 from port 20 to 100...
[+] Port 21 is open (Service: ftp)
[+] Port 80 is open (Service: http)
Port scan completed.
Report saved to port_scan_report_YYYYMMDD_HHMMSS.txt
```

## Applications
- Security auditing and vulnerability assessment.
- Network troubleshooting.
- Identifying active services on a network.

## License
This project is licensed under the GNU General Public License v3.0 License. See the `LICENSE` file for more information.

## Contact
For feedback or contributions, contact **ParthXD7** via [GitHub](https://github.com/ParthXD7).

