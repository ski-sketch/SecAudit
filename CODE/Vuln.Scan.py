import json
import logging
import nmap
import concurrent.futures
import re
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Vulnerability database (unchanged from original)
vulnerability_db = {
    "apache": {
        "2.4.49": ["CVE-2021-41773", "CVE-2021-42013"],
        "2.4.48": ["CVE-2021-39275"],
        "2.4.46": ["CVE-2020-9490", "CVE-2020-11984"]
    },
    "nginx": {
        "1.21.1": ["CVE-2021-23017"],
        "1.20.1": ["CVE-2021-23017"],
        "1.19.10": ["CVE-2021-23017"]
    },
    "openssh": {
        "8.4": ["CVE-2021-28041"],
        "8.3": ["CVE-2020-15778"],
        "7.9": ["CVE-2018-15473"]
    },
    "mysql": {
        "8.0.25": ["CVE-2021-2307"],
        "5.7.34": ["CVE-2021-2307"],
        "5.6.51": ["CVE-2021-2307"]
    },
    "postgresql": {
        "13.3": ["CVE-2021-32027"],
        "12.7": ["CVE-2021-32027"],
        "11.12": ["CVE-2021-32027"]
    },
    "php": {
        "7.4.21": ["CVE-2021-21703"],
        "7.3.28": ["CVE-2021-21703"],
        "7.2.34": ["CVE-2020-7069"]
    },
    "python": {
        "3.9.5": ["CVE-2021-3177"],
        "3.8.10": ["CVE-2021-3177"],
        "3.7.10": ["CVE-2021-3177"]
    },
    "java": {
        "8u291": ["CVE-2021-2161"],
        "11.0.11": ["CVE-2021-2161"],
        "16.0.1": ["CVE-2021-2161"]
    },
    "nodejs": {
        "14.17.0": ["CVE-2021-22918"],
        "12.22.1": ["CVE-2021-22918"],
        "10.24.1": ["CVE-2021-22918"]
    },
    "docker": {
        "20.10.7": ["CVE-2021-21284"],
        "19.03.15": ["CVE-2020-15257"],
        "18.09.9": ["CVE-2019-13139"]
    }
}

def validate_targets(targets):
    """Validate the format of target IP addresses or hostnames."""
    valid_targets = []
    for target in targets:
        if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", target):  # Simple IPv4 validation
            valid_targets.append(target)
        else:
            logging.warning(f"Invalid target format: {target}")
    return valid_targets

def check_vulnerabilities_locally(service, version):
    """Check for vulnerabilities in the local database."""
    if service in vulnerability_db:
        if version in vulnerability_db[service]:
            return vulnerability_db[service][version]
    return []

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
                vulnerabilities = check_vulnerabilities_locally(service, version)
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
