# Port Scanner Using Python

A powerful and professional port scanner written in Python. This tool scans a target IP for open ports within a specified range and provides additional features like OS fingerprinting, service detection, and data visualization.

## Features
- OS Fingerprinting
- Open Port Detection
- Export Results to JSON
- Visualize Open Ports with Matplotlib
- User-friendly Command-line Interface

## Prerequisites
Ensure the following are installed on your system:
- Python 3.12 or higher
- Virtualenv
- Dependencies: `schedule`, `tqdm`, `matplotlib`, `flask`, `scapy`

## Installation
1. Clone the repository or download the source code.
2. Navigate to the project directory:
   ```bash
   cd PortScanner

3. Create a Python virtual environment:

   ```bash
   python3 -m venv venv
   source venv/bin/activate

4. Install the required Python libraries:
   ```bash
   pip install schedule tqdm matplotlib flask scapy

## Usage

1. Run the scanner:
   ```bash
   sudo python port_scanner.py
2. Enter the target IP address, start port, and end port as prompted.
3. View the scan results in the terminal and as a JSON file (scan_results.json).
4. Visualize open ports with an interactive Matplotlib chart.

## Project Structure

>port_scanner.py: Main script
>scan_results.json: Output file with scan results
>README.md: Project documentation

## Contribution

Feel free to fork this project and submit pull requests to add features or improve functionality.