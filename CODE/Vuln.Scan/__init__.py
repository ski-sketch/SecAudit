import json
import logging
import nmap
import concurrent.futures
import re
import requests
import atexit  # To handle saving data when the program ends
import signal  # To handle termination signals
import sys
from datetime import datetime
from threading import Timer
import colorlog

# Configure logging
handler = colorlog.StreamHandler()
handler.setFormatter(colorlog.ColoredFormatter(
    "%(log_color)s%(levelname)s: %(message_log_color)s%(message)s",
    log_colors={
        'INFO': 'green',
        'ERROR': 'red',
    },
    secondary_log_colors={
        'message': {
            'INFO': 'blue',
            'ERROR': 'blue',
        }
    }
))

logger = colorlog.getLogger('vuln-scan')
logger.addHandler(handler)
logger.setLevel(logging.INFO)

# NVD API Configuration
API_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
API_KEY = "50191d62-ffce-4f78-9aea-f086524355bc"

scan_results = {}  # Store scan results globally
TIMEOUT_LIMIT = 2 * 60  # Timeout after 5 minutes (in seconds)

def save_results_to_file(filename="scan_results.json"):
    """Save scan results to a file when the program ends."""
    try:
        with open(filename, "w") as file:
            json.dump(scan_results, file, indent=4)
        logger.info(f"Results saved to {filename}. You can now review the scan results and vulnerabilities found.")
    except Exception as e:
        logger.error(f"Error saving results to file: {e}")

# Register the function to be called at exit
atexit.register(save_results_to_file)

def signal_handler(sig, frame):
    """Handles termination signals to ensure results are saved when the program is stopped."""
    logger.info("Program interrupted, saving results...")
    save_results_to_file()
    sys.exit(0)

# Register the signal handler for graceful termination
signal.signal(signal.SIGINT, signal_handler)

def validate_targets(targets):
    """Validate the format of target IP addresses or hostnames."""
    valid_targets = []
    for target in targets:
        if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", target):  # Simple IPv4 validation
            valid_targets.append(target)
        else:
            logger.warning(f"Invalid target format: {target}. Please provide a valid IP address.")
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

        # Extract relevant CVE information
        vulnerabilities = []
        if "result" in response.json() and "CVE_Items" in response.json()["result"]:
            for item in response.json()["result"]["CVE_Items"]:
                cve_id = item["cve"]["CVE_data_meta"]["ID"]
                description = item["cve"]["description"]["description_data"][0]["value"]
                vulnerabilities.append({"cve_id": cve_id, "description": description})
        return vulnerabilities

    except requests.exceptions.HTTPError as e:
        if response.status_code == 404:
            logger.info(f"404 Error: No vulnerabilities found for {service} version {version}.")  # Simplified message
        elif response.status_code == 403:
            logger.error(f"403 Error: Forbidden access for {service} version {version}. Check your API key or permissions.")
        else:
            logger.error(f"HTTP Error {response.status_code}: Unable to fetch vulnerabilities for {service} version {version}.")
        return []
    except requests.exceptions.RequestException as e:
        logger.error(f"Network issue or invalid request for {service} version {version}: {e}.")
        return []
    except Exception as e:
        logger.error(f"Unexpected error while fetching vulnerabilities for {service} version {version}: {e}.")
        return []

def check_vulnerabilities(service, version):
    """Check vulnerabilities via the NVD API."""
    return fetch_vulnerabilities_from_nvd(service, version)

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
            "vulnerabilities": vulnerabilities_found if vulnerabilities_found else "No vulnerabilities found"  # Clear message
        }
    except Exception as e:
        logger.error(f"Error scanning target {target}: {e}. This may be due to an issue with the scan arguments, the network, or the target itself.")
        return {
            "target": target,
            "scan_args": scan_args,
            "timestamp": datetime.now().isoformat(),
            "error": f"Scan failed: {e}. Please check the scan arguments, the network, or the target."
        }

def run_scan(targets, scan_types, max_workers=10):
    """Run scans concurrently on a list of targets."""
    validated_targets = validate_targets(targets)
    if not validated_targets:
        logger.error("No valid targets provided. Please check your input.")
        return {}

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
                    scan_results[target] = scan_results.get(target, [])
                    scan_results[target].append(result)
            except Exception as exc:
                logger.error(f"{target_info} generated an exception: {exc}")

    return scan_results

def start_timeout_timer():
    """Start a timeout timer to automatically stop the program after 5 minutes."""
    timer = Timer(TIMEOUT_LIMIT, timeout_callback)
    timer.start()

def timeout_callback():
    """Callback function when the timeout is reached."""
    logger.error("Timeout reached. The scan process will stop and results will be saved.")
    save_results_to_file()
    sys.exit(0)

if __name__ == "__main__":
    start_timeout_timer()  # Start the 5-minute timeout
    targets = ["127.0.0.1"]  # Replace with your target(s)
    scan_types = ["-sS", "-sU", "-sT", "-sA", "-sW", "-sM", "-sN", "-sO", "-sP", "-sV", "-sC"]  # Scan types unchanged
    logger.info("Starting vulnerability scan...")
    results = run_scan(targets, scan_types)
    logger.info("Vulnerability scan completed.")