ARP and MAC Script

Useful script to audit L2 and L3 switches to pull together device MAC and IP addresses and connected switchport.  Output into csv file.

#!/usr/bin/env python3

import csv
import re
from getpass import getpass
from netmiko import ConnectHandler


# ---------------------------------------------------------
# CONFIGURATION
# ---------------------------------------------------------

VLANS = [881, 882, 883, 884, 888]

# Replace these IP addresses and names with your stacks.
SWITCHES = [
    {
        "name": "<switch name",
        "device_type": "cisco_ios",
        "host": "<device ip>",
    },   
    
]


# ---------------------------------------------------------
# ARP DEVICE
# ---------------------------------------------------------
#
# This should normally be the router/core switch that owns
# the SVIs/default gateways for VLANs <VLAN ID's>.
#
# Example:
#
# interface Vlan881
#   ip address x.x.x.x
#
# If the 3650 stacks themselves own the VLAN interfaces,
# set:
#
# ARP_DEVICE = None
#

ARP_DEVICE = {
    "name": "<switch name>",
    "device_type": "cisco_ios",
    "host": "<device IP>",
}


OUTPUT_FILE = "vlan_audit.csv"


# ---------------------------------------------------------
# HELPER FUNCTIONS
# ---------------------------------------------------------

def normalize_mac(mac):
    """
    Convert MAC addresses into Cisco xxxx.xxxx.xxxx format.

    Examples:

        aa:bb:cc:dd:ee:ff -> aabb.ccdd.eeff
        aa-bb-cc-dd-ee-ff -> aabb.ccdd.eeff
        aabb.ccdd.eeff    -> aabb.ccdd.eeff
    """

    mac = re.sub(r"[^0-9a-fA-F]", "", mac).lower()

    if len(mac) != 12:
        return mac

    return f"{mac[0:4]}.{mac[4:8]}.{mac[8:12]}"


def connect(device, username, password, enable_password):
    """
    Connect to Cisco IOS device using SSH and enter enable mode.
    """

    connection_info = {
        "device_type": device["device_type"],
        "host": device["host"],
        "username": username,
        "password": password,
        "secret": enable_password,
        "fast_cli": False,
    }

    print(
        f"Connecting to {device['name']} "
        f"({device['host']})..."
    )

    connection = ConnectHandler(**connection_info)

    # Enter Cisco privileged EXEC / enable mode.
    if not connection.check_enable_mode():
        connection.enable()

    # Confirm that enable mode succeeded.
    if not connection.check_enable_mode():
        connection.disconnect()

        raise RuntimeError(
            f"Failed to enter enable mode on "
            f"{device['name']} ({device['host']})"
        )

    return connection


def get_arp_table(connection):
    """
    Read ARP entries for the VLANs being audited.

    Returns a dictionary keyed by (VLAN, MAC), for example:

        {
            (882, "0018.851e.1c17"): "172.21.229.65",
            (883, "000b.3c81.138a"): "172.21.229.141",
        }
    """

    arp_table = {}

    for vlan in VLANS:
        print(f"  Reading ARP table for VLAN {vlan}...")

        command = f"show ip arp vlan {vlan}"

        output = connection.send_command(
            command,
            read_timeout=30
        )

        for line in output.splitlines():
            parts = line.split()

            if len(parts) < 6:
                continue

            if parts[0].lower() != "internet":
                continue

            ip_address = parts[1]
            mac_address = parts[3]
            interface = parts[5]

            if mac_address.lower() in ["incomplete", "-"]:
                continue

            mac_address = normalize_mac(mac_address)

            vlan_match = re.search(
                r"Vlan(\d+)",
                interface,
                re.IGNORECASE
            )

            if vlan_match:
                arp_vlan = int(vlan_match.group(1))
            else:
                arp_vlan = vlan

            arp_table[(arp_vlan, mac_address)] = ip_address

            print(
                f"    ARP: VLAN {arp_vlan} "
                f"{ip_address} {mac_address} {interface}"
            )

    print(
        f"  Total relevant ARP entries: "
        f"{len(arp_table)}"
    )

    return arp_table

def get_mac_table(connection, vlan):
    """
    Read the MAC address table for one VLAN.

    Returns:

        [
            {
                "vlan": 881,
                "mac": "aaaa.bbbb.cccc",
                "port": "Gi1/0/10"
            }
        ]
    """

    results = []

    command = f"show mac address-table vlan {vlan}"

    output = connection.send_command(
        command,
        read_timeout=30
    )

    # Typical Cisco 3650 output:
    #
    #  881    aabb.ccdd.eeff    DYNAMIC     Gi1/0/10
    #
    mac_regex = re.compile(
        r"^\s*(\d+)\s+"
        r"([0-9a-fA-F\.:-]+)\s+"
        r"(?:DYNAMIC|STATIC)\s+"
        r"(\S+)",
        re.IGNORECASE
    )

    for line in output.splitlines():

        match = mac_regex.search(line)

        if not match:
            continue

        mac_vlan = int(match.group(1))
        mac_address = normalize_mac(match.group(2))
        port = match.group(3)

        if mac_vlan != vlan:
            continue

        # Ignore entries that aren't useful physical ports.
        if port.lower() in [
            "cpu",
            "router",
            "switch",
        ]:
            continue

        results.append({
            "vlan": vlan,
            "mac": mac_address,
            "port": port,
        })

    return results


def get_interface_description(connection, port):
    """
    Attempt to retrieve the description configured on a port.
    """

    command = (
        f"show interfaces {port} description"
    )

    output = connection.send_command(
        command,
        read_timeout=15
    )

    for line in output.splitlines():

        line = line.strip()

        if not line:
            continue

        if line.lower().startswith("interface"):
            continue

        if port.lower() in line.lower():

            parts = line.split()

            # IOS usually returns:
            #
            # Interface  Status  Protocol  Description
            #
            # so anything after the first few columns may be
            # the configured description.
            if len(parts) >= 4:
                return " ".join(parts[3:])

    return ""



def get_port_mode(connection, port):
    """
    Return a simple port classification.

    Possible values:
        ACCESS
        TRUNK
        PORT-CHANNEL
        ROUTED
        UNKNOWN
    """

    if port.lower().startswith("po"):
        return "PORT-CHANNEL"

    try:
        output = connection.send_command(
            f"show interfaces {port} switchport",
            read_timeout=15
        )
    except Exception:
        return "UNKNOWN"

    output_lower = output.lower()

    if "switchport: disabled" in output_lower:
        return "ROUTED"

    operational_match = re.search(
        r"Operational Mode:\s*(.+)",
        output,
        re.IGNORECASE
    )

    if operational_match:
        mode = operational_match.group(1).strip().lower()

        if "trunk" in mode:
            return "TRUNK"

        if "static access" in mode or mode == "access":
            return "ACCESS"

    admin_match = re.search(
        r"Administrative Mode:\s*(.+)",
        output,
        re.IGNORECASE
    )

    if admin_match:
        mode = admin_match.group(1).strip().lower()

        if "trunk" in mode:
            return "TRUNK"

        if "static access" in mode or mode == "access":
            return "ACCESS"

    return "UNKNOWN"


# ---------------------------------------------------------
# MAIN
# ---------------------------------------------------------

def main():

    print("=" * 65)
    print("Cisco VLAN Device Audit")
    print("=" * 65)
    print()

    # -----------------------------------------------------
    # LOGIN DETAILS
    # -----------------------------------------------------
    #
    # Credentials are requested when the script runs.
    # They are NOT stored in this file.
    #

    username = input("SSH Username: ")
    ssh_password = getpass("SSH Password: ")

    print()
    print(
        "Enter the Cisco enable password."
    )
    print(
        "If the enable password is the same as the SSH "
        "password, just press ENTER."
    )

    enable_password = getpass("Enable Password: ")

    if not enable_password:
        enable_password = ssh_password

    print()

    # -----------------------------------------------------
    # BUILD ARP TABLE
    # -----------------------------------------------------

    global_arp_table = {}

    if ARP_DEVICE is not None:

        print("=" * 65)
        print("Getting IP/MAC information from ARP device")
        print("=" * 65)

        try:

            arp_connection = connect(
                ARP_DEVICE,
                username,
                ssh_password,
                enable_password
            )

            global_arp_table = get_arp_table(
                arp_connection
            )

            arp_connection.disconnect()

            print(
                f"  Found {len(global_arp_table)} "
                f"relevant ARP entries."
            )

        except Exception as exc:

            print()
            print(
                f"ERROR connecting to ARP device "
                f"{ARP_DEVICE['name']}:"
            )

            print(exc)

            print()
            print(
                "Continuing switch audit, but IP addresses "
                "may be blank."
            )

    # -----------------------------------------------------
    # AUDIT THE THREE SWITCH STACKS
    # -----------------------------------------------------

    results = []

    for switch in SWITCHES:

        print()
        print("=" * 65)
        print(
            f"Auditing {switch['name']} "
            f"({switch['host']})"
        )
        print("=" * 65)

        try:

            connection = connect(
                switch,
                username,
                ssh_password,
                enable_password
            )

        except Exception as exc:

            print()
            print(
                f"ERROR connecting to "
                f"{switch['name']}:"
            )

            print(exc)
            continue

        # If there is no separate ARP/core device,
        # get ARP information directly from this stack.
        if ARP_DEVICE is None:

            arp_table = get_arp_table(
                connection
            )

        else:

            arp_table = global_arp_table

        # -------------------------------------------------
        # CHECK EACH VLAN
        # -------------------------------------------------

        for vlan in VLANS:

            print(
                f"  Auditing VLAN {vlan}..."
            )

            try:

                mac_entries = get_mac_table(
                    connection,
                    vlan
                )

            except Exception as exc:

                print(
                    f"    ERROR reading VLAN {vlan}: "
                    f"{exc}"
                )

                continue

            print(
                f"    Found {len(mac_entries)} "
                f"MAC entries."
            )

            for entry in mac_entries:

                mac_address = entry["mac"]
                port = entry["port"]

                ip_address = arp_table.get(
                    (vlan, mac_address),
                    ""
                )

                # Try to obtain interface description.
                try:

                    description = (
                        get_interface_description(
                            connection,
                            port
                        )
                    )

                except Exception:

                    description = ""

                try:
                    port_mode = get_port_mode(
                        connection,
                        port
                    )
                except Exception:
                    port_mode = "UNKNOWN"

                if ip_address:
                    match_status = "MATCHED"
                elif port_mode in ["TRUNK", "PORT-CHANNEL"]:
                    match_status = "NO ARP - UPLINK/TRANSIT"
                else:
                    match_status = "NO ARP ENTRY"

                if not ip_address:
                    print(
                        f"    UNMAPPED: VLAN {vlan} "
                        f"{mac_address} on {port} "
                        f"({port_mode})"
                    )

                results.append({
                    "stack": switch["name"],
                    "switch_ip": switch["host"],
                    "vlan": vlan,
                    "mac_address": mac_address,
                    "ip_address": ip_address,
                    "switch_port": port,
                    "port_description": description,
                    "port_mode": port_mode,
                    "match_status": match_status,
                })

        connection.disconnect()

    # -----------------------------------------------------
    # WRITE CSV REPORT
    # -----------------------------------------------------

    fieldnames = [
        "stack",
        "switch_ip",
        "vlan",
        "mac_address",
        "ip_address",
        "switch_port",
        "port_description",
        "port_mode",
        "match_status",
    ]

    with open(
        OUTPUT_FILE,
        "w",
        newline="",
        encoding="utf-8"
    ) as csvfile:

        writer = csv.DictWriter(
            csvfile,
            fieldnames=fieldnames
        )

        writer.writeheader()
        writer.writerows(results)

    # -----------------------------------------------------
    # SUMMARY
    # -----------------------------------------------------

    print()
    print("=" * 65)
    print("AUDIT COMPLETE")
    print("=" * 65)

    print(
        f"Total MAC entries found: {len(results)}"
    )

    entries_with_ip = sum(
        1
        for row in results
        if row["ip_address"]
    )

    entries_without_ip = (
        len(results) - entries_with_ip
    )

    print(
        f"Entries with IP address: {entries_with_ip}"
    )

    print(
        f"Entries without IP address: "
        f"{entries_without_ip}"
    )

    unmatched_transit = sum(
        1
        for row in results
        if not row["ip_address"]
        and row["port_mode"] in ["TRUNK", "PORT-CHANNEL"]
    )

    unmatched_edge = sum(
        1
        for row in results
        if not row["ip_address"]
        and row["port_mode"] not in ["TRUNK", "PORT-CHANNEL"]
    )

    print(
        f"Unmatched entries on trunk/port-channel: "
        f"{unmatched_transit}"
    )

    print(
        f"Unmatched entries on edge/other ports: "
        f"{unmatched_edge}"
    )

    print()
    print(
        f"CSV report written to: {OUTPUT_FILE}"
    )

    print("=" * 65)


if __name__ == "__main__":
    main()
