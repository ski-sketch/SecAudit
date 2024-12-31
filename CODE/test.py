import json
import logging
import nmap
import concurrent.futures
import re
import requests
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# NVD API Configuration
API_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/1.0"
API_KEY = "50191d62-ffce-4f78-9aea-f086524355bc"

def validate_targets(targets):
    """Validate the format of target IP addresses or hostnames."""
    valid_targets = []
    for target in targets:
        if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", target):  # Simple IPv4 validation
            valid_targets.append(target)
        else:
            logging.warning(f"Invalid target format: {target}")
    return valid_targets

def fetch_vulnerabilities_from_nvd(service, version):
    """Fetch vulnerabilities from the live NVD API."""
    try:
        params = {
            "keyword": f"{service} {version}",
            "apiKey": API_KEY
        }
        response = requests.get(API_BASE_URL, params=params, timeout=10)
        response.raise_for_status()
        data = response.json()

        # Extract relevant CVE information
        vulnerabilities = []
        if "result" in data and "CVE_Items" in data["result"]:
            for item in data["result"]["CVE_Items"]:
                cve_id = item["cve"]["CVE_data_meta"]["ID"]
                description = item["cve"]["description"]["description_data"][0]["value"]
                vulnerabilities.append({"cve_id": cve_id, "description": description})
        return vulnerabilities
    except Exception as e:
        logging.error(f"Error fetching vulnerabilities for {service} {version}: {e}")
        return []

def check_vulnerabilities(service, version):
    """Check vulnerabilities via the NVD API."""
    return fetch_vulnerabilities_from_nvd(service, version)

def save_results_to_file(results, filename="scan_results.json"):
    """Save scan results to a file."""
    try:
        with open(filename, "w") as file:
            json.dump(results, file, indent=4)
        logging.info(f"Results saved to {filename}")
    except Exception as e:
        logging.error(f"Error saving results to file: {e}")

def perform_scan(target, scan_args):
    """Perform an Nmap scan on the target."""
    try:
        nm = nmap.PortScanner()
        nm.scan(target, arguments=scan_args)
        results = nm[target]
        vulnerabilities_found = []

        for proto in results.all_protocols():
            for port, details in results[proto].items():
                service = details.get('name', 'unknown')
                version = details.get('version', 'unknown')
                vulnerabilities = check_vulnerabilities(service, version)
                if vulnerabilities:
                    vulnerabilities_found.append({
                        "port": port,
                        "protocol": proto,
                        "service": service,
                        "version": version,
                        "vulnerabilities": vulnerabilities
                    })

        return {
            "target": target,
            "scan_args": scan_args,
            "timestamp": datetime.now().isoformat(),
            "vulnerabilities": vulnerabilities_found if vulnerabilities_found else "None found"
        }
    except Exception as e:
        logging.error(f"Error scanning target {target}: {e}")
        return {
            "target": target,
            "scan_args": scan_args,
            "timestamp": datetime.now().isoformat(),
            "error": str(e)
        }

def run_scan(targets, scan_types, max_workers=10):
    """Run scans concurrently on a list of targets."""
    validated_targets = validate_targets(targets)
    if not validated_targets:
        logging.error("No valid targets provided.")
        return {}

    results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_target = {
            executor.submit(perform_scan, target, scan_type): f"{target} ({scan_type})"
            for target in validated_targets
            for scan_type in scan_types
        }
        for future in concurrent.futures.as_completed(future_to_target):
            target_info = future_to_target[future]
            try:
                result = future.result()
                target = result.get("target")
                if target:
                    results[target] = results.get(target, [])
                    results[target].append(result)
            except Exception as exc:
                logging.error(f"{target_info} generated an exception: {exc}")
    return results

if __name__ == "__main__":
    targets = ["127.0.0.1"]  # Replace with your target(s)
    scan_types = ["-sS", "-sU", "-sT", "-sA", "-sW", "-sM", "-sN", "-sO", "-sP", "-sV", "-sC"]  # Scan types unchanged
    logging.info("Starting vulnerability scan...")
    results = run_scan(targets, scan_types)
    save_results_to_file(results)
    logging.info("Vulnerability scan completed.")
