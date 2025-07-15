# speech_attack_sim/test_harness/logger.py
import csv
import os

LOG_FILE = "data/logs/misbehavior_log.csv"

def log_result(row):
    # Appends a result row to the misbehavior log CSV file
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    exists = os.path.exists(LOG_FILE)
    with open(LOG_FILE, mode='a', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=row.keys())
        if not exists:
            writer.writeheader()
        writer.writerow(row)

def log_result_to_file(row, log_file):
    # Appends a result row to the specified log CSV file
    os.makedirs(os.path.dirname(log_file), exist_ok=True)
    exists = os.path.exists(log_file)
    with open(log_file, mode='a', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=row.keys())
        if not exists:
            writer.writeheader()
        writer.writerow(row)