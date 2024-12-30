import concurrent.futures
import json
import logging
import nmap

# Logging setup
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Expanded local vulnerability data
vulnerability_db = {
    "Apache": {
        "2.4.1": ["CVE-2020-1234", "CVE-2020-5678"],
        "2.4.3": ["CVE-2019-1234"]
    },
    "OpenSSL": {
        "1.1.1": ["CVE-2019-1559"],
        "1.0.2": ["CVE-2016-2108"]
    },
    "nginx": {
        "1.18.0": ["CVE-2021-23017"],
        "1.19.0": ["CVE-2021-23017"]
    },
    "MySQL": {
        "5.7": ["CVE-2019-2974"],
        "8.0": ["CVE-2020-14812"]
    },
    "PostgreSQL": {
        "12.3": ["CVE-2020-25695"],
        "13.1": ["CVE-2020-25695"]
    },
    "SSH": {
        "7.4": ["CVE-2018-15473"],
        "8.0": ["CVE-2019-6111"]
    },
    "Tomcat": {
        "9.0.0": ["CVE-2020-9484"],
        "10.0.0": ["CVE-2021-30640"]
    },
    "Redis": {
        "5.0": ["CVE-2020-14147"],
        "6.0": ["CVE-2021-21309"]
    },
    "MongoDB": {
        "4.2": ["CVE-2020-7921"],
        "4.4": ["CVE-2021-20329"]
    }
}

# Function to check for vulnerabilities with local database (returns a list of CVEs)
def check_vulnerabilities_locally(service, version):
    if service in vulnerability_db:
        if version in vulnerability_db[service]:
            return vulnerability_db[service][version]
    return []

# Function to save results to a file
def save_results_to_file(results, filename="scan_results.json"):
    with open(filename, "w") as file:
        json.dump(results, file, indent=4)
    logging.info(f"Results saved to {filename}")

# Function to perform a scan
def perform_scan(target, scan_type):
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

        return {"target": target, "vulnerabilities": vulnerabilities_found if vulnerabilities_found else None}
    except Exception as e:
        logging.error(f"Error scanning target {target}: {e}")
        return {"error": str(e)}

# Function to run the scan with multithreading
def run_scan(targets, scan_types, max_workers=10):
    results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_target = {executor.submit(perform_scan, target, scan_type): target for target in targets for scan_type in scan_types}
        for future in concurrent.futures.as_completed(future_to_target):
            target = future_to_target[future]
            try:
                results[target] = future.result()
            except Exception as exc:
                logging.error(f"{target} generated an exception: {exc}")
    return results

if __name__ == "__main__":
    targets = ["127.0.0.1"]  # Replace with your target(s)
    scan_types = ["-sS", "-sU", "-sT", "-sA", "-sW", "-sM", "-sN", "-sO", "-sP", "-sV", "-sC"]  # Scan with all protocols, excluding -sR
    results = run_scan(targets, scan_types)
    save_results_to_file(results)
    logging.info("Vulnerability scan completed.")