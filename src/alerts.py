from rich.console import Console
from rich.panel import Panel

console = Console()


def display_alerts(alerts):
    if not alerts:
        console.print("\n[green]✓ No security alerts detected.[/green]")
        return

    console.print(f"\n[bold red]Detected {len(alerts)} Security Alert(s)[/bold red]\n")

    severity_colors = {
        "CRITICAL": "bold red",
        "HIGH": "red",
        "MEDIUM": "yellow",
        "LOW": "green"
    }

    for alert in alerts:
        color = severity_colors.get(alert["severity"], "white")

        body = f"""
User: {alert['user']}
Source IP: {alert['source_ip']}
"""

        if "attempts" in alert:
            body += f"Failed Attempts: {alert['attempts']}\n"

        if "description" in alert:
            body += f"\nDescription:\n{alert['description']}"

        if "mitre_id" in alert:
            body += (
                f"\n\nMITRE ATT&CK\n"
                f"Technique: {alert['mitre_id']}\n"
                f"Name: {alert['mitre_name']}"
            )

        if "recommendation" in alert:
            body += (
                f"\n\nRecommendation:\n"
                f"{alert['recommendation']}"
            )

        panel = Panel(
            body.strip(),
            title=f"[{color}]{alert['severity']} - {alert['title']}[/{color}]",
            border_style=color
        )

        console.print(panel)