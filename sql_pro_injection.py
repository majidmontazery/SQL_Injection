import requests
import time

def test_sql_injection(url, params, payloads, method="GET"):
    """Tests a target URL for SQL injection vulnerabilities."""
    
    vulnerable_params = []

    for param in params:
        for payload in payloads:
            print(f"[*] Testing {param} with payload: {payload}")

            if method.upper() == "GET":
                target_url = f"{url}?{param}={payload}"
                start_time = time.time()
                try:
                    response = requests.get(target_url, timeout=10)
                    elapsed_time = time.time() - start_time
                except requests.RequestException as e:
                    print(f"[-] Request failed: {e}")
                    continue

            elif method.upper() == "POST":
                start_time = time.time()
                try:
                    response = requests.post(url, data={param: payload}, timeout=10)
                    elapsed_time = time.time() - start_time
                except requests.RequestException as e:
                    print(f"[-] Request failed: {e}")
                    continue

            else:
                print("[-] Invalid HTTP method.")
                return

            if check_vulnerability(response.text) or elapsed_time > 4:
                print(f"[+] SQL Injection vulnerability found in parameter '{param}' with payload: {payload}")
                vulnerable_params.append((param, payload))
                break  # Stop testing this parameter if it's vulnerable

    log_results(url, vulnerable_params)

    if vulnerable_params:
        print("\n[+] SQL Injection vulnerabilities found. Check scan_results.txt for details.")
    else:
        print("\n[-] No SQL Injection vulnerabilities detected.")

def check_vulnerability(response_text):
    """Checks if the response contains common SQL error messages."""
    error_signatures = [
        "You have an error in your SQL syntax;",
        "Warning: mysql_fetch_array()",
        "Unclosed quotation mark",
        "SQLSTATE[HY000]",
        "Microsoft OLE DB Provider for SQL Server"
    ]

    return any(error in response_text for error in error_signatures)

def log_results(url, vulnerable_params):
    """Logs the results to a file."""
    with open("scan_results.txt", "a") as f:  # Use 'a' to append results
        f.write(f"SQL Injection Scan Report\n")
        f.write(f"Target URL: {url}\n")
        f.write(f"--------------------------------------\n")

        if vulnerable_params:
            f.write("[+] Vulnerabilities Found:\n")
            for param, payload in vulnerable_params:
                f.write(f" - Parameter: {param}\n   Payload: {payload}\n\n")
        else:
            f.write("[-] No vulnerabilities found.\n")

def get_payloads_from_file():
    """Load SQL injection payloads from a file."""
    file_path = input("Enter the path to the payload file: ").strip()
    payloads = []
    try:
        with open(file_path, "r") as file:
            payloads = [line.strip() for line in file.readlines()]
        print(f"[+] Loaded {len(payloads)} payloads from {file_path}")
    except FileNotFoundError:
        print(f"[-] File not found: {file_path}")
    return payloads

def get_manual_payloads():
    """Get SQL injection payloads from user input manually."""
    payloads = []
    print("\nEnter SQL injection payloads (Type 'done' to finish):")
    while True:
        payload = input(f"{len(payloads) + 1}. ").strip()
        if payload.lower() == "done":
            return payloads
        payloads.append(payload)
    return payloads

def get_payloads():
    """Prompt the user for how they want to load payloads."""
    choice = input("Do you want to load payloads from a file (f) or enter them manually (m)? (f/m): ").strip().lower()
    if choice == "f":
        return get_payloads_from_file()
    elif choice == "m":
        return get_manual_payloads()
    else:
        print("[-] Invalid choice. Defaulting to manual input.")
        return get_manual_payloads()

def main():
    url = input("Enter the target URL (e.g., http://example.com/page.php): ").strip()
    params = input("Enter the parameters to test (comma-separated, e.g., id,username,email): ").strip().split(',')
    method = input("Enter HTTP method (GET or POST): ").strip().upper()

    # Get payloads from the user
    payloads = get_payloads()
    
    print("\n[+] Performing SQL Injection test...\n")
    test_sql_injection(url, params, payloads, method)

if __name__ == "__main__":
    main()
