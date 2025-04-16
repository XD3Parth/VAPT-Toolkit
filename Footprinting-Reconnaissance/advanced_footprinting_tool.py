import requests
import socket
import whois
from dns import resolver, reversename
from ipwhois import IPWhois
from bs4 import BeautifulSoup
import ssl
import json
from urllib.parse import urlparse
import subprocess
import tkinter as tk
from tkinter import ttk, messagebox

ssl._create_default_https_context = ssl._create_unverified_context

def get_ip(domain):
    try:
        ip = socket.gethostbyname(domain)
        return f"IP Address: {ip}\n"
    except Exception as e:
        return f"Error fetching IP: {e}\n"

def perform_whois(domain):
    try:
        whois_info = whois.whois(domain)
        return f"WHOIS Information:\n{json.dumps(whois_info, indent=4, default=str)}\n"
    except Exception as e:
        return f"Error performing WHOIS lookup: {e}\n"

def dns_records(domain):
    result = "DNS Records:\n"
    try:
        for record_type in ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']:
            try:
                answers = resolver.resolve(domain, record_type)
                for answer in answers:
                    result += f"{record_type}: {answer}\n"
            except Exception as e:
                result += f"Error fetching {record_type} records: {e}\n"
    except Exception as e:
        result += f"DNS Error: {e}\n"
    return result

def reverse_dns(ip):
    try:
        reversed_dns = reversename.from_address(ip)
        resolved = str(resolver.resolve(reversed_dns, "PTR")[0])
        return f"Reverse DNS: {resolved}\n"
    except Exception as e:
        return f"Error performing reverse DNS: {e}\n"

def ip_geolocation(ip):
    try:
        obj = IPWhois(ip)
        details = obj.lookup_rdap(asn_methods=['dns', 'whois', 'http'])
        return f"IP Geolocation Information:\n{json.dumps(details, indent=4)}\n"
    except Exception as e:
        return f"Error fetching geolocation: {e}\n"

def ssl_certificate_info(domain):
    try:
        parsed_url = urlparse(f"https://{domain}")
        conn = ssl.create_default_context().wrap_socket(socket.socket(socket.AF_INET), server_hostname=parsed_url.netloc)
        conn.connect((parsed_url.netloc, 443))
        cert = conn.getpeercert()
        result = "SSL Certificate Information:\n"
        for key, value in cert.items():
            result += f"{key}: {value}\n"
        return result
    except Exception as e:
        return f"Error fetching SSL Certificate information: {e}\n"

def web_scraping(domain):
    try:
        url = f"http://{domain}"
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        result = "Web Scraping:\n"
        result += f"Title: {soup.title.string if soup.title else 'No title found'}\n"
        meta = soup.find('meta', attrs={'name': 'description'})
        result += f"Meta Description: {meta['content'] if meta else 'No meta description found'}\n"
        result += "Links:\n"
        for link in soup.find_all('a', href=True):
            result += f"{link['href']}\n"
        return result
    except Exception as e:
        return f"Web Scraping Error: {e}\n"

def traceroute(domain):
    try:
        result = subprocess.run(["traceroute", domain], capture_output=True, text=True)
        return f"Traceroute:\n{result.stdout}\n"
    except Exception as e:
        return f"Error performing traceroute: {e}\n"

def osint_search(domain):
    try:
        google_search_url = f"https://www.google.com/search?q=site:{domain}"
        return f"OSINT Search Results:\nGoogle Dork: {google_search_url}\n[Note: Copy and paste the above link into a browser for OSINT results]\n"
    except Exception as e:
        return f"Error performing OSINT search: {e}\n"

def perform_footprinting(domain):
    if not domain:
        return "Domain cannot be empty.\n"

    result = f"Gathering Information for Domain: {domain}\n"
    ip = get_ip(domain)
    result += ip

    if ip and "Error" not in ip:
        ip_address = ip.split(": ")[1].strip()
        result += perform_whois(domain)
        result += dns_records(domain)
        result += reverse_dns(ip_address)
        result += ip_geolocation(ip_address)
        result += ssl_certificate_info(domain)
        result += web_scraping(domain)
        result += traceroute(domain)
        result += osint_search(domain)

    return result

def start_gui():
    def on_submit():
        domain = domain_entry.get().strip()
        result = perform_footprinting(domain)
        output_text.delete(1.0, tk.END)
        output_text.insert(tk.END, result)

    root = tk.Tk()
    root.title("Advanced Footprinting Tool")

    frame = ttk.Frame(root, padding="10")
    frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

    ttk.Label(frame, text="Enter Domain:").grid(row=0, column=0, sticky=tk.W)
    domain_entry = ttk.Entry(frame, width=40)
    domain_entry.grid(row=0, column=1, sticky=(tk.W, tk.E))

    submit_button = ttk.Button(frame, text="Submit", command=on_submit)
    submit_button.grid(row=0, column=2, padx=5)

    output_text = tk.Text(frame, wrap="word", width=80, height=30)
    output_text.grid(row=1, column=0, columnspan=3, pady=10)

    ttk.Scrollbar(frame, orient="vertical", command=output_text.yview).grid(row=1, column=3, sticky=(tk.N, tk.S))
    output_text['yscrollcommand'] = ttk.Scrollbar(frame, orient="vertical").set

    root.mainloop()

if __name__ == "__main__":
    start_gui()
