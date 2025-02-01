import re
import csv

log_file_path = "<php_log_file_path>"
csv_file_path = "<suspicious_activities_php.csv_output_file_path>"

# Define regular expressions to extract relevant information from log lines
log_entry_regex = re.compile(
    r'(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) -  (?P<timestamp>\d{2}/\w+/\d{4}:\d{2}:\d{2}:\d{2} \+\d{4}) "(?P<method>\w+) (?P<url>[^"]+)" (?P<status>\d{3}) (?P<path>[^ ]+) (?P<bytes>\d+) (?P<time>\d+\.\d+) (?P<other>\d+) (?P<percent>\d+\.\d+)%'
)
warning_regex = re.compile(
    r'\[(?P<timestamp>\d{2}-\w+-\d{4} \d{2}:\d{2}:\d{2})\] WARNING: (?P<message>.+)'
)

# Data structure to store suspicious activities
suspicious_activities = []

# Read the log file line by line
with open(log_file_path, 'r') as log_file:
    for line in log_file:
        log_entry_match = log_entry_regex.match(line)
        warning_match = warning_regex.match(line)
        
        if log_entry_match:
            log_entry = log_entry_match.groupdict()
            suspicious_activities.append(log_entry)
            print(log_entry)  # Print the log entry
        elif warning_match:
            warning_entry = warning_match.groupdict()
            suspicious_activities.append(warning_entry)
            print(warning_entry)  # Print the warning entry

# Write the suspicious activities to a CSV file
with open(csv_file_path, 'w', newline='') as csv_file:
    fieldnames = ['ip', 'timestamp', 'method', 'url', 'status', 'path', 'bytes', 'time', 'other', 'percent', 'message']
    writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
    
    writer.writeheader()
    for activity in suspicious_activities:
        writer.writerow(activity)