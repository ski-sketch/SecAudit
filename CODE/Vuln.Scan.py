import concurrent.futures
import json
import logging
import threading
import time
import tkinter as tk
from tkinter import messagebox, ttk

import nmap

# Logging setup
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Function to handle missing dependencies
def check_dependencies():
    try:
        import nmap
    except ImportError:
        messagebox.showerror("Error", "nmap module is not installed. Please install it using 'pip install python-nmap'.")
        exit()

# Sample local vulnerability data (normally would be read from a file)
vulnerability_db = {
    "Apache": {
        "2.4.1": ["CVE-2020-1234", "CVE-2020-5678"],
        "2.4.3": ["CVE-2019-1234"]
    },
    "OpenSSL": {
        "1.1.1": ["CVE-2019-1559"],
        "1.0.2": ["CVE-2016-2108"]
    }
}

# Function to check for vulnerabilities with local database (returns a list of CVEs)
def check_vulnerabilities_locally(service, version):
    # Check if service is in the vulnerability database
    if service in vulnerability_db:
        # Check if the version is vulnerable and return the CVEs
        if version in vulnerability_db[service]:
            return vulnerability_db[service][version]  # Return a list of CVEs
    return []  # No vulnerabilities found

# Function to save results to a file
def save_results_to_file(results, filename="scan_results.json"):
    with open(filename, "w") as file:
        json.dump(results, file, indent=4)
    logging.info(f"Results saved to {filename}")

# Function to perform a scan
def perform_scan(target, scan_type="-A"):
    try:
        nm = nmap.PortScanner()
        nm.scan(target, arguments=scan_type)
        results = nm[target]
        vulnerabilities_found = []

        for proto in results.all_protocols():
            for port in results[proto].keys():
                service = results[proto][port].get('name', 'unknown')
                version = results[proto][port].get('version', 'unknown')
                vulnerabilities = check_vulnerabilities_locally(service, version)
                if vulnerabilities:
                    vulnerabilities_found.append({
                        "port": port,
                        "service": service,
                        "version": version,
                        "vulnerabilities": vulnerabilities
                    })

        # Return result with vulnerabilities if any, otherwise return no vulnerabilities
        return {"target": target, "vulnerabilities": vulnerabilities_found if vulnerabilities_found else None}
    except Exception as e:
        logging.error(f"Error scanning target {target}: {e}")
        return {"error": str(e)}

# Function to run the scan with multithreading
def run_scan(targets, scan_type, max_workers=10):
    results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
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
    check_dependencies()  # Ensure dependencies are met

    def update_progress():
        progress.start()

    def finish_progress():
        progress.stop()
        progress.pack_forget()

    def display_results(results):
        for target, result in results.items():
            if "error" in result:
                results_text.insert(tk.END, f"Error scanning {target}: {result['error']}\n\n")
            else:
                if result["vulnerabilities"]:
                    results_text.insert(tk.END, f"Scan result for {target}:\n")
                    for vuln in result["vulnerabilities"]:
                        vuln_status = f"Vulnerability found on port {vuln['port']} (Service: {vuln['service']}, Version: {vuln['version']}):\n"
                        for cve in vuln["vulnerabilities"]:
                            vuln_status += f"    - {cve}\n"
                        results_text.insert(tk.END, vuln_status + "\n")
                else:
                    results_text.insert(tk.END, f"Scan result for {target}: No Vulnerabilities Found\n\n")
        results_text.yview(tk.END)

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

        # Start scan in a separate thread to keep GUI responsive
        def run_scan_thread():
            update_progress()
            results = run_scan(target_list, scan_type)
            save_results_to_file(results)  # Save the results to a file
            finish_progress()
            display_results(results)
            messagebox.showinfo("Scan Complete", "Scan results are displayed and saved to scan_results.json.")

        threading.Thread(target=run_scan_thread, daemon=True).start()

    root = tk.Tk()
    root.title("Vuln.scan")

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

    # Add progress bar for feedback during scan
    progress = ttk.Progressbar(root, orient="horizontal", length=200, mode="indeterminate")
    progress.pack()

    # Add Text widget for displaying results
    results_text = tk.Text(root, height=15, width=50)
    results_text.pack()

    root.mainloop()

if __name__ == "__main__":
    start_gui()
