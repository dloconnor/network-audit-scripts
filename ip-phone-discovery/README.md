#!/usr/bin/env python3


from netmiko import ConnectHandler
import csv

# -------------------------------
# FILES
# -------------------------------
inventory_file = "ipphone_discovery.csv"
output_file = "ip_phones.csv"

phones = []

# -------------------------------
# READ SWITCH INVENTORY
# -------------------------------
with open(inventory_file, newline='', encoding='utf-8') as f:
    reader = csv.DictReader(f)
    switches = [row for row in reader]

print("Switches loaded:")
for sw in switches:
    print(sw)

# -------------------------------
# LOOP SWITCHES
# -------------------------------
for sw in switches:

    print(f"\nConnecting to {sw['hostname']} ({sw['ip']})...")

    device = {
        "device_type": sw["device_type"],
        "host": sw["ip"],
        "username": sw["username"],
        "password": sw["password"],
        "secret": sw["enable"],
        "timeout": 30,
        "global_delay_factor": 2,
        "session_log": "debug_phones.txt"
    }

    try:
        connection = ConnectHandler(**device)

        # -------------------------------
        # PROMPT / ENABLE
        # -------------------------------
        prompt = connection.find_prompt()
        hostname = prompt.rstrip("#>").strip()
        print(f"Prompt detected: {prompt}")

        if ">" in prompt:
            try:
                connection.enable()
            except Exception as e:
                print(f"⚠️ Enable failed on {hostname}: {e}")

        # Disable paging
        connection.send_command("terminal length 0", expect_string=r"[#>]")

        # -------------------------------
        # GET ARP TABLE (IP ↔ MAC)
        # -------------------------------
        print(f"Collecting ARP table from {hostname}...")

        arp_output = connection.send_command(
            "show ip arp",
            expect_string=r"[#>]",
            read_timeout=120
        )

        arp_table = {}

        for line in arp_output.splitlines():
            parts = line.split()
            if len(parts) >= 4:
                ip = parts[1]
                mac = parts[3].replace(".", "").lower()
                arp_table[mac] = ip

        # -------------------------------
        # GET CDP NEIGHBORS
        # -------------------------------
        print(f"Collecting CDP data from {hostname}...")

        cdp_output = connection.send_command(
            "show cdp neighbors detail",
            expect_string=r"[#>]",
            read_timeout=120
        )

        current_device = {}

        for line in cdp_output.splitlines():
            line = line.strip()

            if "Device ID:" in line:
                current_device = {}
                device_id = line.split("Device ID:")[1].strip()

                if device_id.startswith("SEP"):
                    mac = device_id.replace("SEP", "").lower()
                    current_device["mac"] = mac

            elif "Platform:" in line:
                if "Phone" in line:
                    device_type = line.split("Platform:")[1].split(",")[0].strip()
                    current_device["type"] = device_type

            elif "Interface:" in line:
                interface = line.split("Interface:")[1].split(",")[0].strip()
                current_device["port"] = interface

            # When complete, match IP from ARP
            if all(k in current_device for k in ("mac", "type", "port")):

                mac = current_device["mac"]
                ip_address = arp_table.get(mac, "UNKNOWN")

                print(f"📞 {hostname} → MAC: {mac} IP: {ip_address}")

                phones.append([
                    hostname,
                    sw["ip"],
                    current_device["port"],
                    mac,
                    ip_address,
                    current_device["type"]
                ])

                current_device = {}

        connection.disconnect()

    except Exception as e:
        print(f"❌ Failed on {sw['hostname']} ({sw['ip']}): {e}")

# -------------------------------
# EXPORT CSV
# -------------------------------
with open(output_file, "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow([
        "Hostname",
        "Switch IP",
        "Port",
        "MAC",
        "IP Address",
        "Device Type"
    ])
    writer.writerows(phones)

print(f"\n✅ Phone inventory exported to {output_file}")
