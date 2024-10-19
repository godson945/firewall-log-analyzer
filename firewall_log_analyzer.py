import re
from collections import Counter

# Path to the firewall log file
LOG_FILE_PATH = 'sample_logs/firewall.log'

def read_log_file(file_path):
    with open(file_path, 'r') as f:
        return f.readlines()

def parse_log_entry(entry):
    pattern = r"(?P<timestamp>\S+ \S+) - Source: (?P<source>\S+) - Destination: (?P<destination>\S+) - Port: (?P<port>\d+) - Action: (?P<action>\S+)"
    match = re.match(pattern, entry)
    if match:
        return match.groupdict()
    return None

def analyze_logs(log_entries):
    denied_attempts = []
    allowed_attempts = []
    
    for entry in log_entries:
        log_data = parse_log_entry(entry)
        if log_data:
            if log_data['action'] == 'DENIED':
                denied_attempts.append(log_data)
            else:
                allowed_attempts.append(log_data)
    
    return denied_attempts, allowed_attempts

def summarize(denied_attempts, allowed_attempts):
    denied_sources = [entry['source'] for entry in denied_attempts]
    denied_ports = [entry['port'] for entry in denied_attempts]

    print("Firewall Log Summary:")
    print(f"Total DENIED attempts: {len(denied_attempts)}")
    print(f"Top DENIED Sources: {Counter(denied_sources).most_common(3)}")
    print(f"Top DENIED Ports: {Counter(denied_ports).most_common(3)}")

def main():
    log_entries = read_log_file(LOG_FILE_PATH)
    denied_attempts, allowed_attempts = analyze_logs(log_entries)
    summarize(denied_attempts, allowed_attempts)

if __name__ == "__main__":
    main()
