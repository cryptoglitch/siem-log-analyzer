from rich.console import Console
from rich.table import Table

from alerts import display_alerts
from parser import load_logs
from detections import run_all_detections

console = Console()


def display_logs(events):
    table = Table(title="Security Log Events")

    table.add_column("Timestamp", style="cyan")
    table.add_column("Event ID", style="yellow")
    table.add_column("User", style="green")
    table.add_column("Source IP", style="magenta")
    table.add_column("Event", style="white")

    for event in events:
        table.add_row(
            event["timestamp"],
            event["event_id"],
            event["user"],
            event["source_ip"],
            event["event"]
        )

    console.print(table)


events = load_logs()

console.print(f"\n[bold cyan]Loaded {len(events)} security events.[/bold cyan]\n")

display_logs(events)

alerts = run_all_detections(events)

display_alerts(alerts)