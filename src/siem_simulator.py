import json
import os
import datetime

# Dummy log data representing enterprise activity stream
raw_logs_pool = [
    "2026-10-26 10:00:01 INFO User 'john' logged in successfully from 192.168.1.50",
    "2026-10-26 10:02:14 WARN User 'admin' login failed - Reason: Failed password attempt from 203.0.113.5",
    "2026-10-26 10:03:45 INFO Database query executed: SELECT name FROM products WHERE id = 10",
    "2026-10-26 10:04:12 CRIT Web Application input payload detected: UNION SELECT null, username, password FROM users",
    "2026-10-26 10:05:22 WARN User 'guest' executed unauthorized terminal sequence: sudo su -",
    "2026-10-26 10:06:50 INFO System health heartbeat check status: OK"
]

def run_siem_engine():
    # Ensure logs folder exists
    os.makedirs('logs', exist_ok=True)
    
    # Write sample raw logs to file path
    log_file_path = os.path.join('logs', 'system_activity.log')
    with open(log_file_path, 'w') as f:
        for entry in raw_logs_pool:
            f.write(entry + "\n")
            
    # Load detection JSON rule configurations
    with open(os.path.join('config', 'siem_rules.json'), 'r') as rules_file:
        rules_data = json.load(rules_file)
        
    alert_output_path = os.path.join('logs', 'siem_alerts.txt')
    alert_count = 0
    
    with open(alert_output_path, 'w') as alert_file:
        alert_file.write(f"--- SIEM ALERTS CORRELATION OUTPUT GENERATED ON {datetime.date.today()} ---\n\n")
        
        # Ingest and scan raw logs against rules matrix
        for log in raw_logs_pool:
            for rule in rules_data["detection_rules"]:
                if rule["trigger_condition"] in log:
                    alert_count += 1
                    alert_msg = (
                        f"[ALERT #{alert_count}] -> SEVERITY: {rule['severity']}\n"
                        f"RULE MATCHED: {rule['rule_name']} (ID: {rule['rule_id']})\n"
                        f"TRIGGER LOG: {log}\n"
                        f"-----------------------------------------------------------\n"
                    )
                    print(alert_msg)
                    alert_file.write(alert_msg)
                    
    print(f"[SUCCESS] SIEM analysis complete. Total {alert_count} critical incidents flagged inside 'logs/siem_alerts.txt'")

if __name__ == "__main__":
    run_siem_engine()
