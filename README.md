# Wordpress PHP Login Access V1

This project analyzes login access logs from a PHP application on Wordpress website and identifies suspicious activities. The results are saved to a CSV file.

## Prerequisites

- Python 3.x
- Required Python libraries: `re`, `csv`

## Setup

1. Clone the repository:
   ```sh
   git clone https://github.com/YOUR_USERNAME/YOUR_REPO.git](https://github.com/sanba06c/wordpress-login-access-automatic-analysis.git
   cd YOUR_REPO
2. Update the log_file_path and csv_file_path variables in analysis_login_access_v1_public.py with the appropriate file paths:
   log_file_path = "/path/to/your/php_log_file.log"
   csv_file_path = "/path/to/your/suspicious_activities_output.csv"

## Usage

Run the script:
python3 analysis_login_access_v1_public.py
The script will read the log file, analyze it for suspicious activities, and save the results to the specified CSV file.
