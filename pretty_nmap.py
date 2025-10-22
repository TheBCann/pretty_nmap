#!/usr/bin/python
import asyncio
import shlex
from rich.console import Console
from rich.table import Table
from rich.live import Live

console = Console()


ports_data = {}


def generate_table() -> Table:
    """Generates a new table from the ports_data dictionary."""
    table = Table(
        show_header=True, header_style="bold magenta", title="Nmap Scan Results"
    )
    table.add_column("PORT", style="cyan", no_wrap=True)
    table.add_column("STATE", style="yellow")
    table.add_column("SERVICE", style="yellow")
    table.add_column("VERSION", style="yellow")

    sorted_ports = sorted(ports_data.keys(), key=lambda p: int(p.split("/")[0]))

    for port in sorted_ports:
        data = ports_data[port]
        table.add_row(port, data["state"], data["service"], data["version"])

    return table


async def start_scan(shell_command):
    try:
        with Live(generate_table(), refresh_per_second=4) as live:
            start_parsing_details = False

            process = await asyncio.create_subprocess_exec(
                *shell_command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            async for line in process.stdout:
                decoded_line = line.decode("utf-8").strip()

                if "Discovered open port" in decoded_line:
                    parts = decoded_line.split()
                    port_id = parts[3]
                    if port_id not in ports_data:
                        ports_data[port_id] = {
                            "state": "[yellow]open[/yellow]",
                            "service": "[yellow]discovering...[/yellow]",
                            "version": "[yellow]discovering...[/yellow]",
                        }
                        live.update(generate_table())

                elif "PORT" in decoded_line and "STATE" in decoded_line:
                    start_parsing_details = True
                    continue

                elif start_parsing_details:
                    parts = decoded_line.split()
                    if len(parts) >= 2 and "/" in parts[0]:
                        port_id = parts[0]
                        if port_id in ports_data:
                            ports_data[port_id]["state"] = parts[1]
                            ports_data[port_id]["service"] = (
                                parts[2] if len(parts) > 2 else ""
                            )
                            ports_data[port_id]["version"] = (
                                " ".join(parts[3:]) if len(parts) > 3 else ""
                            )
                            live.update(generate_table())

        console.print("\n[bold green][*] Scan Complete[/bold green]")

    except FileNotFoundError:
        print(f"Error: The command '{shell_command[0]}' was not found")
    except Exception as e:
        print(f"An unexpected error occured: {e}")


async def main():
    command = "nmap -sV -v -T4 scanme.nmap.org"
    shell_command = shlex.split(command)
    await start_scan(shell_command)


if __name__ == "__main__":
    asyncio.run(main())
