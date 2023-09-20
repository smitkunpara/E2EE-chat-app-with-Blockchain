import subprocess
import socket
import psutil
import requests
import time
from urllib3.exceptions import NewConnectionError, MaxRetryError

# Function to get network connection information
def get_network_info(interface):
    network_interfaces = psutil.net_if_addrs()

    print(f"Interface: {interface}")
    for addr in network_interfaces[interface]:
        if addr.family == socket.AF_INET:
            print(f"  IP Address: {addr.address}")
        elif addr.family == psutil.AF_LINK:
            print(f"  MAC Address: {addr.address}")

# Function to get WiFi SSID (name) the device is connected to
def get_wifi_ssid():
    wifi_ssid = "Unknown"
    try:
        networks = subprocess.run(["netsh", "wlan", "show", "interfaces"], capture_output=True, text=True)
        output = networks.stdout
        lines = output.split('\n')
        for line in lines:
            if "SSID" in line:
                wifi_ssid = line.split(":")[1].strip()
                break
    except Exception as e:
        print("Error:", str(e))
    return wifi_ssid

# Function to determine connection type and name
def get_connection_type_and_name():
    network_interfaces = psutil.net_if_stats()
    wifi_interface = None
    ethernet_interface = None

    for interface, stats in network_interfaces.items():
        if stats.isup and interface != 'Loopback Pseudo-Interface 1':
            if 'Wi-Fi' in interface or 'Wireless' in interface:
                wifi_interface = interface
            elif 'Ethernet' in interface:
                ethernet_interface = interface
    
    if wifi_interface:
        wifi_ssid = get_wifi_ssid()
        print(f"Connected via: WiFi")
        print(f"WiFi Network Name: {wifi_ssid}")
        get_network_info(wifi_interface)
    elif ethernet_interface:
        print(f"Connected via: Ethernet")
        get_network_info(ethernet_interface)
    else:
        print("Not connected to WiFi or Ethernet")

# Function to get ISP details based on public IP
def get_isp_details(public_ip):
    try:
        response = requests.get(f"https://ipapi.co/{public_ip}/org/")
        isp = response.text.strip()
        if isp:
            print(f"ISP: {isp}")
        else:
            print("ISP: Unknown ISP")
    except NewConnectionError:
        print("Internet is disconnected.")
    except MaxRetryError:
        print("Internet is disconnected.")
    except Exception as e:
        print("Error:", str(e))
        print("ISP: Unknown ISP")

# Flag to indicate whether the internet is connected
internet_connected = True

# Store initial values
initial_ip = socket.gethostbyname(socket.gethostname())
local_mac = ':'.join(['{:02x}'.format((int(x, 16) + 2) % 256) for x in initial_ip.split('.')])
initial_public_ip = "Unknown"

# Main function
def connection_check():
    initial_output = None
    ip_or_mac_changed = False  # Flag to track changes in IP or MAC

    while True:
        if not internet_connected:
            print("Internet is disconnected. Waiting for reconnection...")
            while not internet_connected:
                try:
                    # Check if the internet is reconnected
                    public_ip = requests.get("https://api64.ipify.org?format=json").json().get("ip", "Unknown")
                    if public_ip != "Unknown":
                        internet_connected = True
                        print("Internet is reconnected.")
                    time.sleep(5)  # Wait for a while before checking again
                except requests.exceptions.RequestException:
                    time.sleep(5)  # Wait for a while before checking again

        current_ip = socket.gethostbyname(socket.gethostname())
        current_mac = ':'.join(['{:02x}'.format((int(x, 16) + 2) % 256) for x in current_ip.split('.')])

        if current_ip != initial_ip:
            print("IP address has been changed.")
            ip_or_mac_changed = True

        if current_mac != local_mac:
            print("MAC address has been changed.")
            ip_or_mac_changed = True

        get_connection_type_and_name()

        try:
            public_ip = requests.get("https://api64.ipify.org?format=json").json().get("ip", "Unknown")

            # Ignore changes in public IP address
            if initial_public_ip == "Unknown":
                initial_public_ip = public_ip
            elif public_ip != initial_public_ip:
                print(f"Public IP Address has been changed: {initial_public_ip} -> {public_ip}")
                initial_public_ip = public_ip

            # Capture the current output
            current_output = subprocess.run(["ipconfig"], capture_output=True, text=True)
            current_output = current_output.stdout

            # Check if the output has changed
            if initial_output is not None and current_output != initial_output:
                print("Output has changed.")
                break

            initial_output = current_output
        except requests.exceptions.RequestException:
            internet_connected = False  # Internet is disconnected
            print("Internet is disconnected.")

        if ip_or_mac_changed:
            break

        # Sleep for a while before checking again (e.g., every 5 seconds)
        time.sleep(5)
