# Advanced Footprinting Tool

The **Advanced Footprinting Tool** is a comprehensive reconnaissance utility designed for cybersecurity professionals, ethical hackers, and network administrators. It provides detailed information about a target domain using a user-friendly graphical interface (GUI).

## Features

- **IP Address Lookup**: Retrieve the IP address of the target domain.
- **WHOIS Information**: Perform WHOIS lookups to gather domain registration details.
- **DNS Records**: Query and display DNS records such as A, MX, NS, TXT, and CNAME.
- **Reverse DNS Lookup**: Get the PTR record for the target IP.
- **IP Geolocation**: Fetch geolocation and ownership information for an IP address.
- **SSL Certificate Information**: Extract SSL certificate details from the target domain.
- **Web Scraping**: Extract webpage title, meta description, and hyperlinks from the target website.
- **Traceroute**: Perform a traceroute to the target domain.
- **OSINT Search**: Generate a Google Dork link for Open Source Intelligence (OSINT) research.
- **Graphical User Interface (GUI)**: Easy-to-use interface powered by Tkinter.

## Prerequisites

Ensure Python is installed on your system. The tool requires the following Python libraries:

```bash
pip install requests whois dnspython ipwhois beautifulsoup4
```

## How to Use

1. **Download and Run**:
   Save the script as `advanced_footprinting_tool.py`.
   
2. **Execute**:
   - Double-click the Python file to launch the GUI.
   - Alternatively, run the script from the terminal:
     ```bash
     python advanced_footprinting_tool.py
     ```

3. **Enter Target Domain**:
   - Enter a domain name in the input field and click **Submit**.
   - The results will be displayed in the text area.

## Output Example

```plaintext
Gathering Information for Domain: example.com
IP Address: 93.184.216.34
WHOIS Information:
{
    "domain_name": "example.com",
    "registrar": "ICANN",
    ...
}
DNS Records:
A: 93.184.216.34
MX: mail.example.com
...
```

## Notes

- **Traceroute** requires a valid traceroute utility installed on your system.
- The tool is for educational purposes and legal penetration testing only. Ensure you have permission before scanning domains.

## Contribution

Feel free to contribute to the project by submitting issues or pull requests on GitHub.

## License

This project is licensed under the MIT License. See the LICENSE file for details.

