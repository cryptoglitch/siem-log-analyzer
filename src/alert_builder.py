from mitre import enrich_alert


def create_alert(severity, title, user, source_ip, attempts=None, description=None):
    alert = {
        "severity": severity,
        "title": title,
        "user": user,
        "source_ip": source_ip
    }

    if attempts is not None:
        alert["attempts"] = attempts

    if description:
        alert["description"] = description

    return enrich_alert(alert)
