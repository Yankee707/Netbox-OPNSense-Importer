# OPNsense Sync Script for NetBox

This script synchronizes network configuration from an OPNsense firewall into NetBox. It is designed to run as a **NetBox Custom Script**.

## Features

1.  **Interface Sync**: Imports all interfaces (LAN, WAN, VLANs, WireGuard, etc.) from OPNsense.
2.  **IP Address Sync**: Assigns the correct IP addresses and subnets to those interfaces.
3.  **ARP Discovery**: Fetches the ARP table from OPNsense and automatically assigns IP addresses to **other** devices/VMs in NetBox based on their MAC address.

## Installation

1.  Copy `opnsense_sync.py` to your NetBox scripts directory (usually `/opt/netbox/netbox/scripts/`).
2.  Ensure the file is readable by the NetBox user.
3.  Restart the NetBox RQ worker (or the entire NetBox service) to pick up the new script.
    ```bash
    sudo systemctl restart netbox
    # OR
    sudo systemctl restart netbox-rq
    ```

## Usage

1.  Log in to NetBox.
2.  Navigate to **Customization** > **Scripts**.
3.  Click on **OPNsense Sync**.
4.  Fill in the configuration form and click **Run Script**.

## Configuration: VM vs. Device

The script asks: **"Is this a Virtual Machine?"**

*   **CHECKED (Default):** Use this if your OPNsense is running as a VM (e.g., on Proxmox).
    *   The script will look for an existing **Virtual Machine** in NetBox with the name you provided.
    *   *Tip:* If you are using the Proxmox Import Plugin, use the exact name of the VM as it appears in Proxmox. The script will attach the OPNsense interfaces and IPs to that existing VM.
*   **UNCHECKED:** Use this if your OPNsense is a physical hardware appliance.
    *   The script will look for a **Device** in NetBox.
    *   If it doesn't exist, it will create a new Device (Manufacturer: OPNsense, Type: OPNsense VM/Appliance).

## How to Create OPNsense API Keys

To allow NetBox to talk to OPNsense, you need an API Key and Secret.

1.  Log in to your OPNsense web interface.
2.  Go to **System** > **Access** > **Users**.
3.  Click the **+** button to create a new user (e.g., `netbox-sync`), or edit an existing user.
4.  Click the **🎟️** button to generate a new key.
5.  A file will automatically download.
    *   This file contains the **key** and **secret**. Keep these safe!
6.  **Permissions:**
    *   Click the **pencil icon** (Edit) on the user again.
    *   Scroll to **Effective Privileges** (or Group Memberships if using groups).
    *   Ensure the user has access to:
        *   `Diagnostics: Interface: ARP` (Required for ARP table sync)
        *   `Interfaces: Assign network ports` (Often covers the overview data)
        *   `WireGuard` (Optional, if syncing VPNs)

## Troubleshooting

*   **"Virtual Machine not found"**: Ensure the name in the script form matches the VM name in NetBox exactly.
*   **SSL Errors**: If using self-signed certificates on OPNsense, uncheck the "Verify SSL" box in the script form.
