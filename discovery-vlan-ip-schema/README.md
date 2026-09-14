

from netmiko import ConnectHandler
import csv
import ipaddress

with open("Academic_switch_inventory.csv") as f:
    reader = csv.DictReader(f)
    switches = [row for row in reader]

print("Switches read from CSV:")
for sw in switches:
    print(sw)

inventory_file = "Academic_switch_inventory.csv"
output_file = "network_schema_Academic_switches.csv"

all_schema = []

with open(inventory_file, newline='', encoding='utf-8') as f:
    reader = csv.DictReader(f)
    switches = [row for row in reader]

print("Switches read from CSV:")
for sw in switches:
    print(sw)

for sw in switches:

    print(f"Connecting to {sw['hostname']} ({sw['ip']})...")

    device = {
        "device_type": sw["device_type"],
        "host": sw["ip"],
        "username": sw["username"],
        "password": sw["password"],
        "secret": sw["enable"],
        "global_delay_factor": 2,
        "timeout": 15,
    }

    try:

        connection = ConnectHandler(**device)
        connection.enable()

        # get hostname from device
        hostname_output = connection.send_command("show run | include hostname")
        hostname = hostname_output.split()[1]

        # -----------------------------
        # GET VLAN NAMES
        # -----------------------------
        vlan_output = connection.send_command("show vlan brief")

        vlan_names = {}

        for line in vlan_output.splitlines():

            parts = line.split()

            if len(parts) >= 2 and parts[0].isdigit():

                vlan_id = parts[0]
                vlan_name = parts[1]

                vlan_names[vlan_id] = vlan_name

        # -----------------------------
        # GET VLAN INTERFACE CONFIG
        # -----------------------------

        run_output = connection.send_command("show running-config")

        lines = run_output.splitlines()

        current_vlan = None
        description = ""

        for line in lines:

            line = line.strip()

            if line.startswith("interface Vlan"):

                current_vlan = line.split("Vlan")[1]
                description = ""

            elif line.startswith("description") and current_vlan:

                description = line.replace("description", "").strip()

            elif line.startswith("ip address") and current_vlan:

                parts = line.split()

                ip = parts[2]
                mask = parts[3]

                network = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)

                vlan_name = vlan_names.get(current_vlan, "UNKNOWN")

                all_schema.append([
                    hostname,
                    sw["ip"],
                    current_vlan,
                    vlan_name,
                    description,
                    ip,
                    str(network)
                ])

            elif line.startswith("interface") and not line.startswith("interface Vlan"):

                current_vlan = None

        connection.disconnect()

    except Exception as e:

        print(f"Failed to connect to {sw['hostname']} ({sw['ip']}): {e}")

# save CSV

with open(output_file, "w", newline="") as f:

    writer = csv.writer(f)

    writer.writerow([
        "Hostname",
        "Switch IP",
        "VLAN",
        "VLAN Name",
        "Description",
        "Gateway",
        "Subnet"
    ])

    writer.writerows(all_schema)

print(f"Network schema exported to {output_file}")

