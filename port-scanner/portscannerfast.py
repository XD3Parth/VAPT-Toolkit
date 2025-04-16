import socket
import threading
from queue import Queue
from datetime import datetime
import math

# Function to scan multiple ports simultaneously
def scan_ports(target, ports, timeout, report_file):
    open_ports = []
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            for port in ports:
                if sock.connect_ex((target, port)) == 0:
                    try:
                        service = socket.getservbyport(port)
                    except Exception:
                        service = "Unknown service"
                    result = f"[+] Port {port} is open (Service: {service})"
                    print(result)
                    with open(report_file, "a") as f:
                        f.write(result + "\n")
                    open_ports.append(port)
    except Exception as e:
        for port in ports:
            result = f"[-] Error scanning port {port}: {e}"
            print(result)
            with open(report_file, "a") as f:
                f.write(result + "\n")
    return open_ports

# Worker function for threading
def worker(queue, target, timeout, report_file, total_ports, batch_size):
    while not queue.empty():
        ports = []
        for _ in range(batch_size):
            if not queue.empty():
                ports.append(queue.get())
        remaining = queue.qsize()
        processed = total_ports - remaining
        estimate_time = remaining * (timeout / 1000)
        print(f"Scanning ports {ports}... (Processed: {processed}/{total_ports}, Estimated time left: {math.ceil(estimate_time)} seconds)")
        try:
            scan_ports(target, ports, timeout, report_file)
        finally:
            for _ in ports:
                queue.task_done()

# Main function to perform port scanning
def advanced_port_scanner(target, start_port, end_port, timeout, threads, batch_size):
    start_time = datetime.now()
    report_file = f"port_scan_report_{start_time.strftime('%Y%m%d_%H%M%S')}.txt"
    print(f"Starting port scan on {target} from port {start_port} to {end_port} at {start_time}...")
    print(f"Report will be saved to {report_file}")

    # Validate target
    try:
        target_ip = socket.gethostbyname(target)
        print(f"Resolved target {target} to IP: {target_ip}")
    except socket.gaierror:
        print(f"Error: Unable to resolve target {target}. Exiting.")
        return

    # Create a queue for ports to scan
    queue = Queue()
    total_ports = end_port - start_port + 1
    for port in range(start_port, end_port + 1):
        queue.put(port)

    # Launch worker threads
    threads_list = []
    for _ in range(threads):
        thread = threading.Thread(target=worker, args=(queue, target_ip, timeout, report_file, total_ports, batch_size))
        thread.daemon = True
        thread.start()
        threads_list.append(thread)

    # Wait for all tasks to complete
    queue.join()

    # Ensure all threads are finished
    for thread in threads_list:
        thread.join()

    end_time = datetime.now()
    print(f"Port scan completed at {end_time}.")
    print(f"Total duration: {end_time - start_time}")

if __name__ == "__main__":
    target = input("Enter target IP or hostname: ").strip()
    start_port = int(input("Enter start port (0-65535): "))
    end_port = int(input("Enter end port (0-65535): "))
    timeout = float(input("Enter timeout (seconds): "))
    threads = int(input("Enter number of threads: "))
    batch_size = int(input("Enter number of ports to scan simultaneously (batch size): "))

    if start_port < 0 or end_port > 65535 or start_port > end_port:
        print("Error: Invalid port range. Please enter valid ports within 0-65535.")
    elif batch_size <= 0:
        print("Error: Batch size must be greater than 0.")
    else:
        advanced_port_scanner(target, start_port, end_port, timeout, threads, batch_size)