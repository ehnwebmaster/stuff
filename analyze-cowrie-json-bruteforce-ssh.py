import json
import sys
import glob
import gzip
from datetime import datetime
from collections import Counter

def parse_iso_time(timestamp_str):
    """Parses ISO 8601 timestamps, handling the 'Z' timezone indicator."""
    if timestamp_str.endswith('Z'):
        timestamp_str = timestamp_str[:-1]
    return datetime.fromisoformat(timestamp_str)

def format_number(n):
    """Formats a number with dots as thousand separators (e.g., 323.801)."""
    return f"{n:,}".replace(",", ".")

def analyze_all_logs():
    # 1. Find all files matching the pattern 'cowrie.json*'
    log_files = glob.glob('cowrie.json*')
    
    if not log_files:
        print("Error: No files matching 'cowrie.json*' found in the current directory.")
        return

    print(f"Found {len(log_files)} log file(s) to analyze: {', '.join(log_files)}")
    print("Processing...")

    # Aggregated Data
    failed_attempts = 0
    attacker_ips = []
    target_usernames = []
    target_passwords = []  # New list for passwords
    timestamps = []

    # 2. Iterate through every file found
    for file_path in log_files:
        try:
            # Check if the file is compressed
            if file_path.endswith('.gz'):
                file_opener = gzip.open(file_path, 'rt', encoding='utf-8')
            else:
                file_opener = open(file_path, 'r', encoding='utf-8')

            with file_opener as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    
                    try:
                        entry = json.loads(line)
                    except json.JSONDecodeError:
                        continue 

                    if entry.get('eventid') == 'cowrie.login.failed':
                        failed_attempts += 1
                        
                        src_ip = entry.get('src_ip', 'Unknown')
                        username = entry.get('username', 'Unknown')
                        password = entry.get('password', 'Unknown') # Extract password
                        timestamp = entry.get('timestamp')

                        attacker_ips.append(src_ip)
                        target_usernames.append(username)
                        target_passwords.append(password) # Store password
                        
                        if timestamp:
                            timestamps.append(parse_iso_time(timestamp))
                            
        except Exception as e:
            print(f"Warning: Could not read file {file_path}. Reason: {e}")

    # 3. Check if we found data
    if failed_attempts == 0:
        print("\nNo failed login attempts found in the logs.")
        return

    # --- Calculations ---
    
    unique_ips_count = len(set(attacker_ips))

    if len(timestamps) > 1:
        timestamps.sort()
        start_time = timestamps[0]
        end_time = timestamps[-1]
        duration_seconds = (end_time - start_time).total_seconds()
        
        if duration_seconds > 0:
            rate_per_hour = (failed_attempts / duration_seconds) * 3600
            rate_str = f"~{int(rate_per_hour)}/hour"
        else:
            rate_str = "N/A (Instant)"
    else:
        rate_str = "N/A (Not enough data)"

    # CHANGED: Now getting Top 15
    top_n = 15
    ip_counts = Counter(attacker_ips).most_common(top_n)
    user_counts = Counter(target_usernames).most_common(top_n)
    password_counts = Counter(target_passwords).most_common(top_n) # Count passwords

    # --- Output Generation ---

    print("")
    # Header Table
    print(f"| {'Metric':<30} | {'Value':<15} |")
    print(f"|{'-'*32}|{'-'*17}|")
    print(f"| {'Total failed attempts':<30} | {format_number(failed_attempts):<15} |")
    print(f"| {'Rate':<30} | {rate_str:<15} |")
    print(f"| {'Unique attacking IPs':<30} | {format_number(unique_ips_count):<15} |")
    print("")

    # Top IPs
    print(f"Top {top_n} Attacking IPs")
    print("")
    for ip, count in ip_counts:
        print(f"{format_number(count):<6} attempts - {ip}")
    print("")

    # Top Usernames
    print(f"Most Targeted Usernames (Top {top_n})")
    print("")
    for user, count in user_counts:
        print(f"{format_number(count):<6} - {user}")
    print("")

    # Top Passwords (NEW SECTION)
    print(f"Most Common Passwords (Top {top_n})")
    print("")
    for pwd, count in password_counts:
        # Be careful if password is empty string
        display_pwd = pwd if pwd else "[EMPTY]"
        print(f"{format_number(count):<6} - {display_pwd}")
    print("")

if __name__ == "__main__":
    analyze_all_logs()
