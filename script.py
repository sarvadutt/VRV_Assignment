import re
import csv
from collections import defaultdict

def count_requests(log_file):
    ip_count = defaultdict(int)
    endpoint_count = defaultdict(int)
    failed_logins = defaultdict(int)
    threshold = 10

    with open(log_file, 'r') as file:
        for line in file:
            # Extract the IP address (first part of the log)
            ip = re.findall(r'\d+\.\d+\.\d+\.\d+', line)[0]
            
            # Extract the endpoint (fix regex to only capture path part)
            endpoint = re.findall(r'\"[A-Z]+\s(/[^ ]*)', line)
            if endpoint:
                endpoint = endpoint[0]
                endpoint_count[endpoint] += 1

            # Detect failed login attempts (either 401 or "Invalid credentials")
            if "401" in line or "Invalid credentials" in line:
                failed_logins[ip] += 1

            # Count the total requests made by each IP
            ip_count[ip] += 1

    return ip_count, endpoint_count, failed_logins, threshold

def display_results(ip_count, endpoint_count, failed_logins, threshold):
    print("IP Address           Request Count")
    for ip, count in sorted(ip_count.items(), key=lambda x: x[1], reverse=True):
        print(f"{ip}          {count}")

    print("\nMost Frequently Accessed Endpoint:")
    # Find the most frequently accessed endpoint
    most_accessed = max(endpoint_count, key=endpoint_count.get)
    print(f"{most_accessed} (Accessed {endpoint_count[most_accessed]} times)")

    print("\nSuspicious Activity Detected:")
    print("IP Address           Failed Login Attempts")
    # Check if any IP has exceeded the threshold for failed logins
    for ip, count in failed_logins.items():
        if count > threshold:
            print(f"{ip}          {count}")

def save_results(ip_count, endpoint_count, failed_logins, threshold, filename='log_analysis_results.csv'):
    with open(filename, 'w', newline='') as file:
        writer = csv.writer(file)
        
        # Save IP Address and Request Count
        writer.writerow(['IP Address', 'Request Count'])
        for ip, count in sorted(ip_count.items(), key=lambda x: x[1], reverse=True):
            writer.writerow([ip, count])

        # Save Most Accessed Endpoint and Count
        writer.writerow(['Endpoint', 'Access Count'])
        for endpoint, count in endpoint_count.items():
            writer.writerow([endpoint, count])

        # Save Suspicious Activity and Failed Login Count
        writer.writerow(['IP Address', 'Failed Login Count'])
        for ip, count in failed_logins.items():
            if count > threshold:
                writer.writerow([ip, count])

if __name__ == "__main__":
    log_file = 'sample.log'  # Replace with your actual log file path
    ip_count, endpoint_count, failed_logins, threshold = count_requests(log_file)
    display_results(ip_count, endpoint_count, failed_logins, threshold)
    save_results(ip_count, endpoint_count, failed_logins, threshold)
