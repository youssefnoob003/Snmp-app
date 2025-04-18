from concurrent.futures import ThreadPoolExecutor
import ipaddress
from app.services.snmp_utils import snmp_query, check_snmp_port, snmp_walk
from app.models import Device
from typing import List, Dict, Any

def scan_subnet(subnet, community):
    """Scan a subnet for devices with SNMP port open."""
    try:
        print(f"\nStarting subnet scan: {subnet}")
        network = ipaddress.ip_network(subnet)
        devices = []
        
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = []
            for ip in network.hosts():
                ip_str = str(ip)
                futures.append(executor.submit(check_snmp_port, ip_str, community))
            
            for ip, future in zip(network.hosts(), futures):
                if future.result():
                    devices.append(str(ip))
        
        print(f"\nScan complete. Found {len(devices)} SNMP devices in subnet {subnet}")
        if devices:
            print("Found devices:")
            for device in devices:
                print(f"- {device}")
        return devices
    except Exception as e:
        print(f"Error scanning subnet: {e}")
        return []

def discover_working_oid(device, oids_to_try, oid_type):
    """Try multiple OIDs until finding one that returns a valid value."""
    for oid in oids_to_try:
        try:
            result = snmp_query(device, oid)
            if result['success'] and result['value'] and 'noSuch' not in result['value']:
                print(f"Found working {oid_type} OID: {oid} with value: {result['value']}")
                return oid
        except Exception as e:
            print(f"Error trying {oid_type} OID {oid}: {e}")
    return None

def discover_network_interfaces(device):
    """Discover all network interfaces and their OIDs."""
    interfaces = []
    try:
        # Walk through the interface descriptions (ifDescr)
        walk_result = snmp_walk(device, '1.3.6.1.2.1.2.2.1.2')
        
        if not walk_result['success']:
            print(f"Error walking interfaces: {walk_result.get('error', 'Unknown error')}")
            return interfaces
            
        interface_oids = walk_result['results']

        for oid, name in interface_oids:
            index = oid.split('.')[-1]
            name_lower = name.lower()

            # Only add interfaces that are likely to be active
            if any(keyword in name_lower for keyword in ['wi-fi', 'wifi', 'realtek', 'intel', 'eth']) and \
               not any(keyword in name_lower for keyword in ['vmware', 'virtual', 'hyper-v', 'virtualbox']):
                
                interfaces.append({
                    'index': index,
                    'name': name,
                    'in_octets': f'1.3.6.1.2.1.2.2.1.10.{index}',  # ifInOctets
                    'out_octets': f'1.3.6.1.2.1.2.2.1.16.{index}'  # ifOutOctets
                })
                print(f"Found active interface {index}: {name}")
    except Exception as e:
        print(f"Error discovering interfaces: {e}")
    return interfaces


def find_first_active_interface(device):
    """Find the first interface with traffic."""
    interfaces = discover_network_interfaces(device)
    for interface in interfaces:
        try:
            in_result = snmp_query(device, interface['in_octets'])
            out_result = snmp_query(device, interface['out_octets'])

            # Skip if queries were unsuccessful
            if not in_result['success'] or not out_result['success']:
                continue

            in_str = in_result['value']
            out_str = out_result['value']

            if not in_str.isdigit() and not out_str.isdigit():
                continue  # Skip interface if neither is numeric

            in_bits = int(in_str) if in_str.isdigit() else 0
            out_bits = int(out_str) if out_str.isdigit() else 0

            if in_bits > 0 or out_bits > 0:
                print(f"[INFO] Interface {interface['index']} has traffic. Selected.")
                return interface['index']
        except Exception as e:
            print(f"[WARN] Error checking interface {interface.get('index', 'unknown')}: {e}")
    return None

def find_all_active_interfaces(device):
    """Discover all active interfaces with traffic."""
    print("Discovering all active interfaces...")
    interfaces = discover_network_interfaces(device)
    active_indexes = []

    for interface in interfaces:
        index = interface['index']
        try:
            # Check operational status (ifOperStatus)
            status_oid = f'1.3.6.1.2.1.2.2.1.8.{index}'
            status_result = snmp_query(device, status_oid)
            
            if not status_result['success']:
                print(f"[DEBUG] Couldn't get status for interface {index}: {status_result.get('error')}")
                continue
                
            status = status_result['value']
            if str(status) != '1':
                print(f"[DEBUG] Interface {index} is not up (status: {status})")
                continue  # Skip if not up

            # Check if it has traffic (inOctets and outOctets)
            in_result = snmp_query(device, interface['in_octets'])
            out_result = snmp_query(device, interface['out_octets'])
            
            # Skip if either query failed
            if not in_result['success'] or not out_result['success']:
                continue
                
            in_str = in_result['value']
            out_str = out_result['value']

            if not in_str.isdigit() and not out_str.isdigit():
                continue  # Skip if neither value is numeric

            in_bits = int(in_str) if in_str.isdigit() else 0
            out_bits = int(out_str) if out_str.isdigit() else 0

            if in_bits > 0 or out_bits > 0:
                print(f"[INFO] Interface {index} is up and has traffic. Marked active.")
                active_indexes.append(str(index))

        except Exception as e:
            print(f"[WARN] Error checking interface {index}: {e}")

    return ','.join(active_indexes)

