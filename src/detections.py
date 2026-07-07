from collections import defaultdict

from alert_builder import create_alert


def detect_brute_force(events):
    failed_logins = defaultdict(int)
    alerts = []

    for event in events:
        if event["event_id"] == "4625":
            key = (event["user"], event["source_ip"])
            failed_logins[key] += 1

    for (user, ip), attempts in failed_logins.items():
        if attempts >= 3:
            alerts.append(
                create_alert(
                    severity="HIGH",
                    title="Brute Force Detected",
                    user=user,
                    source_ip=ip,
                    attempts=attempts
                )
            )

    return alerts


def detect_success_after_failures(events):
    failed_logins = defaultdict(int)
    alerts = []

    for event in events:
        key = (event["user"], event["source_ip"])

        if event["event_id"] == "4625":
            failed_logins[key] += 1

        elif event["event_id"] == "4624" and failed_logins[key] >= 3:
            alerts.append(
                create_alert(
                    severity="MEDIUM",
                    title="Successful Login After Failed Logins",
                    user=event["user"],
                    source_ip=event["source_ip"],
                    attempts=failed_logins[key],
                    description="This may indicate a successful brute-force attack."
                )
            )

    return alerts


def detect_powershell_execution(events):
    alerts = []

    for event in events:
        if event["event_id"] == "4104":
            alerts.append(
                create_alert(
                    severity="MEDIUM",
                    title="PowerShell Execution",
                    user=event["user"],
                    source_ip=event["source_ip"],
                    description=(
                        "PowerShell activity was detected. This may be legitimate "
                        "administrator activity or attacker behavior."
                    )
                )
            )

    return alerts


def run_all_detections(events):
    alerts = []
    alerts.extend(detect_brute_force(events))
    alerts.extend(detect_success_after_failures(events))
    alerts.extend(detect_powershell_execution(events))
    return alerts
