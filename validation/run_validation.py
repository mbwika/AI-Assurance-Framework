# speech_attack_sim/validation/run_validation.py
import sys
import csv
csv.field_size_limit(sys.maxsize)
import glob
import os

# Calculate the coverage of misbehavior detection
# Args:
#     log_file (str): Path to the log file
# Returns:
#     float: Coverage percentage of misbehavior detection
def calculate_coverage(log_file):
    total = 0
    triggered = 0
    with open(log_file, newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            total += 1
            if row['misbehavior_detected'].lower() == 'true':
                triggered += 1
    coverage = (triggered / total) * 100 if total else 0
    print(f"Adversarial Trigger Rate: {coverage:.2f}% ({triggered}/{total})")
    return coverage

def validate_all_logs(log_dir="data/logs/"):
    # Validates all CSV log files in the specified directory
    log_files = glob.glob(os.path.join(log_dir, "misbehavior_log_*.csv"))
    for log_file in log_files:
        print(f"\nValidating: {log_file}")
        calculate_coverage(log_file)

if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1:
        for log_file in sys.argv[1:]:
            calculate_coverage(log_file)
    else:
        validate_all_logs()