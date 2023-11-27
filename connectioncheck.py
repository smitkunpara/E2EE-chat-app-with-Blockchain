import socket
import subprocess
import time

def get_ip_address():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("8.8.8.8", 80))
        ip_address = sock.getsockname()[0]
        return ip_address
    except socket.error:
        return None
    finally:
        sock.close()

def get_default_gateway():
    try:
        output = subprocess.check_output(["ipconfig"]).decode("utf-8")
        for line in output.splitlines():
            if "Default Gateway" in line:
                gateway = line.split(":")[1].strip()
                if gateway:
                    return gateway
        return None
    except subprocess.CalledProcessError:
        return None

def get_mac_address(default_gateway):
    try:
        output = subprocess.check_output(["arp", "-a"]).decode("utf-8")
        for line in output.splitlines():
            if default_gateway in line:
                mac_address = line.split()[1].strip()
                if mac_address:
                    return mac_address
        return None
    except subprocess.CalledProcessError:
        return None

