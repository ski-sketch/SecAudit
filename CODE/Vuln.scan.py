import concurrent.futures
import json
import logging
import tkinter as tk
from tkinter import messagebox, ttk

import nmap
import requests

# Logging setup
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Function to save results to a file
def save_results_to_file(results, filename="scan_results.json"):
    with open(filename, "w") as file:
        json.dump(results, file, indent=4)
    logging.info(f"Results saved to {filename}")

# Function to check for common vulnerabilities
def check_vulnerabilities(service, version):
    api_urls = [
        f"https://vulnerabilitydb.example.com/api/v1/{service}/{version}",
        f"https://cveapi.example.com/v2/{service}/{version}"
    ]
    vulnerabilities = []
    for api_url in api_urls:
        try:
            response = requests.get(api_url, timeout=10)
            if response.status_code == 200:
                vulnerabilities.extend(response.json())
        except requests.RequestException as e:
            logging.error(f"Error fetching vulnerabilities from {api_url}: {e}")
    return vulnerabilities

# Function to perform a scan
def perform_scan(target, scan_type="-A"):
    try:
        nm = nmap.PortScanner()
        nm.scan(target, arguments=scan_type)
        results = nm[target]
        for proto in results.all_protocols():
            for port in results[proto].keys():
                service = results[proto][port].get('name', 'unknown')
                version = results[proto][port].get('version', 'unknown')
                vulnerabilities = check_vulnerabilities(service, version)
                results[proto][port]['vulnerabilities'] = vulnerabilities
        return results
    except Exception as e:
        logging.error(f"Error scanning target {target}: {e}")
        return {"error": str(e)}

# Function to run the scan with multithreading
def run_scan(targets, scan_type):
    results = {}
    with concurrent.futures.ThreadPoolExecutor() as executor:
        future_to_target = {executor.submit(perform_scan, target, scan_type): target for target in targets}
        for future in concurrent.futures.as_completed(future_to_target):
            target = future_to_target[future]
            try:
                results[target] = future.result()
            except Exception as exc:
                logging.error(f"{target} generated an exception: {exc}")
    return results

# GUI setup
def start_gui():
    def start_scan():
        targets = target_entry.get().strip()
        if not targets:
            messagebox.showerror("Input Error", "Please enter at least one target.")
            return
        target_list = [t.strip() for t in targets.split(',') if t.strip()]
        if not target_list:
            messagebox.showerror("Input Error", "Please enter valid targets.")
            return
        scan_type = scan_type_var.get()
        results = run_scan(target_list, scan_type)
        save_results_to_file(results)
        messagebox.showinfo("Scan Complete", "Scan results saved to scan_results.json")

    root = tk.Tk()
    root.title("Advanced Network Vulnerability Scanner")

    tk.Label(root, text="Targets (comma-separated):").pack()
    target_entry = tk.Entry(root, width=50)
    target_entry.pack()

    tk.Label(root, text="Select Scan Type:").pack()
    scan_type_var = tk.StringVar(value="-A")
    scan_type_menu = ttk.Combobox(root, textvariable=scan_type_var, state="readonly")
    scan_type_menu['values'] = ["-A", "-sS", "-sV", "-O", "--script vuln"]
    scan_type_menu.pack()

    scan_button = tk.Button(root, text="Start Scan", command=start_scan)
    scan_button.pack()

    root.mainloop()

if __name__ == "__main__":
    start_gui()
