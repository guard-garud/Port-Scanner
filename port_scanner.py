import socket
import threading
from tqdm import tqdm
import json
import logging
import schedule
import time
from scapy.all import sr1, IP, TCP
import matplotlib.pyplot as plt

logging.basicConfig(filename="scan_results.log", level=logging.INFO)

# Initialize variables
results = []
open_ports = []

def scan_port(ip, port):
    """Scan a single port."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        if result == 0:
            try:
                service = socket.getservbyport(port, "tcp")
            except:
                service = "Unknown Service"
            print(f"Port {port}: OPEN ({service})")
            results.append({"port": port, "status": "open", "service": service})
            open_ports.append(port)
            logging.info(f"Port {port}: OPEN ({service})")
        sock.close()
    except Exception as e:
        logging.error(f"Error scanning port {port}: {e}")

def os_fingerprint(ip):
    """Perform OS fingerprinting using Scapy."""
    pkt = IP(dst=ip) / TCP(dport=80, flags="S")
    resp = sr1(pkt, timeout=1, verbose=0)
    if resp and resp.getlayer(TCP).flags == "SA":
        return "Linux/Unix"
    return "Unknown OS"

def plot_results():
    """Visualize scan results."""
    if not open_ports:
        print("No open ports to visualize.")
        return

    plt.bar(open_ports, [1] * len(open_ports), tick_label=open_ports)
    plt.title("Open Ports Visualization")
    plt.xlabel("Ports")
    plt.ylabel("Status")
    plt.show()

def log_results_to_file():
    """Log results to a JSON file."""
    with open("scan_results.json", "w") as f:
        json.dump(results, f, indent=4)
    print("Results saved to scan_results.json")

def schedule_scan(ip, start_port, end_port):
    """Schedule scans to run daily."""
    def job():
        for port in tqdm(range(start_port, end_port + 1), desc="Scheduled Scan"):
            scan_port(ip, port)
        log_results_to_file()
    schedule.every().day.at("10:00").do(job)

    while True:
        schedule.run_pending()
        time.sleep(1)

def main():
    print("Professional Port Scanner")
    target_ip = input("Enter the target IP address: ")

    start_port = int(input("Enter the start port: "))
    end_port = int(input("Enter the end port: "))

    print("\nPerforming OS Fingerprinting...")
    os_info = os_fingerprint(target_ip)
    print(f"Detected OS: {os_info}\n")

    threads = []
    for port in tqdm(range(start_port, end_port + 1), desc="Scanning Ports"):
        thread = threading.Thread(target=scan_port, args=(target_ip, port))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    log_results_to_file()
    plot_results()

    # Schedule scans (uncomment to enable)
    # schedule_scan(target_ip, start_port, end_port)

if __name__ == "__main__":
    main()
