from flask import Blueprint, render_template, request, redirect, url_for, flash
from datetime import datetime
from ipaddress import ip_network
from app.services.snmp_utils import snmp_query, snmp_set
from pysnmp.hlapi import OctetString
from app import db
from app.models import Device, CounterHistory, SNMPLogin
from app.services.discovery import scan_subnet, find_first_active_interface, find_all_active_interfaces

bp = Blueprint('device_routes', __name__)

@bp.route('/')
def index():
    devices = Device.query.all()
    return render_template('index.html', devices=devices)


# ---------- Helpers ---------- #

def create_snmp_login_from_form(snmp_version):
    if snmp_version == 3:
        return SNMPLogin(
            version=3,
            username=request.form.get('username'),
            auth_protocol=request.form.get('auth_protocol'),
            auth_key=request.form.get('auth_password'),
            priv_protocol=request.form.get('priv_protocol'),
            priv_key=request.form.get('priv_password'),
            security_level=request.form.get('auth_level')
        )
    return SNMPLogin(
        version=snmp_version,
        community=request.form.get('community_string')
    )


def detect_os(device):
    sys_descr_oid = '1.3.6.1.2.1.1.1.0'
    try:
        result = snmp_query(device, sys_descr_oid)
        if result['success']:
            descr = result['value'].lower()
            if 'cisco' in descr or 'ios' in descr:
                return 'cisco'
            elif 'windows' in descr:
                return 'windows'
            elif 'linux' in descr:
                return 'linux'
        print(f"Failed to detect OS for {device.ip_address}: {result.get('error', 'Unknown error')}")
        return 'unknown'
    except Exception as e:
        print(f"[WARN] Error detecting OS for {device.ip_address}: {e}")
        return 'unknown'


def detect_model(device):
    try:
        oid = '1.3.6.1.2.1.1.2.0'  # sysObjectID
        result = snmp_query(device, oid)
        if result['success']:
            return Device.get_model_from_oid(Device, result['value'])
        print(f"Failed to detect model for {device.ip_address}: {result.get('error', 'Unknown error')}")
    except Exception as e:
        print(f"[WARN] Error detecting model for {device.ip_address}: {e}")
    return None


def assign_interfaces(device):
    return (
        find_all_active_interfaces(device)
        if device.os == "cisco"
        else find_first_active_interface(device)
    )


def add_single_device(ip, snmp_login):
    device = Device(ip_address=ip, os='unknown', snmp_login=snmp_login)
    db.session.add(snmp_login)

    device.os = detect_os(device)
    model = detect_model(device)
    if model:
        device.model = model

    iface = assign_interfaces(device)
    if iface:
        device.interface_indexes = iface

    db.session.add(device)
    return device


def process_subnet(ip_address, snmp_credential):
    try:
        ip_network(ip_address)
        found = scan_subnet(ip_address, snmp_credential)
        new_devices = []

        for ip in found:
            if not Device.query.filter_by(ip_address=ip).first():
                snmp_login = create_snmp_login_from_form(int(request.form['snmp_version']))
                add_single_device(ip, snmp_login)
                new_devices.append(ip)

        db.session.commit()
        flash(f"Added {len(new_devices)} new device(s) from subnet {ip_address}" if new_devices else "No new devices added.")
    except ValueError:
        flash("Invalid subnet format")


# ---------- Routes ---------- #

@bp.route('/add_device', methods=['POST'])
def add_device():
    ip_address = request.form['ip_address']
    snmp_version = int(request.form['snmp_version'])
    snmp_credential = request.form.get('username') if snmp_version == 3 else request.form.get('community_string')

    if '/' in ip_address:
        process_subnet(ip_address, snmp_credential)
    else:
        snmp_login = create_snmp_login_from_form(snmp_version)
        add_single_device(ip_address, snmp_login)
        db.session.commit()
        flash(f'Device added successfully!')

    return redirect(url_for('device_routes.index'))


@bp.route('/update_cred/<int:device_id>', methods=['POST'])
def update_cred(device_id):
    device = Device.query.get_or_404(device_id)    
    snmp_login = device.snmp_login

    snmp_version = int(request.form['snmp_version'])
    snmp_login.version = snmp_version

    if snmp_version == 3:
        snmp_login.username = request.form.get('username')
        snmp_login.auth_protocol = request.form.get('auth_protocol')
        snmp_login.auth_key = request.form.get('auth_password')
        snmp_login.priv_protocol = request.form.get('priv_protocol')
        snmp_login.priv_key = request.form.get('priv_password')
        snmp_login.security_level = request.form.get('auth_level')
        snmp_login.community = None  # clear if switching from v2c
    else:
        snmp_login.community = request.form.get('community_string')
        snmp_login.username = None
        snmp_login.auth_protocol = None
        snmp_login.auth_key = None
        snmp_login.priv_protocol = None
        snmp_login.priv_key = None
        snmp_login.security_level = None

    device.os = detect_os(device)
    model = detect_model(device)
    if model:
        device.model = model

    iface = assign_interfaces(device)
    if iface and not(device.interface_indexes):
        device.interface_indexes = iface
    db.session.commit()
    flash('SNMP credentials updated successfully!')
    return redirect(url_for('device_routes.index'))


@bp.route('/delete_device/<int:device_id>', methods=['POST'])
def delete_device(device_id):
    device = Device.query.get_or_404(device_id)

    # Delete related CounterHistory entries
    CounterHistory.query.filter_by(device_id=device_id).delete()

    # Store SNMP login for later deletion
    snmp_login = device.snmp_login

    # Delete the device itself
    db.session.delete(device)
    db.session.commit()

    # Delete the SNMP login
    if snmp_login:
        db.session.delete(snmp_login)
        db.session.commit()

    flash('Device, SNMP login, and related history deleted successfully!')
    return redirect(url_for('device_routes.index'))


@bp.route('/query_device/<int:device_id>')
def query_device(device_id):
    device = Device.query.get_or_404(device_id)

    oids = {
        'sysDescr': '1.3.6.1.2.1.1.1.0',
        'sysName': '1.3.6.1.2.1.1.5.0',
        'sysLocation': '1.3.6.1.2.1.1.6.0',
        'sysUpTime': '1.3.6.1.2.1.1.3.0',
        'sysObjectID': '1.3.6.1.2.1.1.2.0',
        'Contact': '1.3.6.1.2.1.1.4.0'
    }

    try:
        # Collect SNMP query results with error handling
        snmp_results = {}
        has_auth_error = False
        has_timeout_error = False
        error_message = None
        
        for k, oid in oids.items():
            result = snmp_query(device, oid)
            if result['success']:
                snmp_results[k] = result['value']
            else:
                snmp_results[k] = "Error retrieving value"
                
                # Track error types for warnings
                if result['error_type'] == 'auth':
                    has_auth_error = True
                    error_message = result['error']
                elif result['error_type'] == 'timeout':
                    has_timeout_error = True
                    error_message = result['error']
                    
                # Don't continue querying if we have connection problems
                if result['error_type'] in ['auth', 'timeout']:
                    break
        
        # Flash appropriate warning for SNMP connectivity issues
        if has_auth_error:
            flash(f"Warning: Potential incorrect SNMP credentials. {error_message}", "warning")
        elif has_timeout_error:
            flash(f"Warning: Device not responding to SNMP queries. {error_message}", "warning")
        
        # Format uptime if available
        try:
            if 'sysUpTime' in snmp_results and snmp_results['sysUpTime'] != "Error retrieving value":
                uptime_seconds = int(snmp_results['sysUpTime']) // 100
                snmp_results['sysUpTimeFormatted'] = f"{uptime_seconds // 3600:02}:{(uptime_seconds % 3600) // 60:02}:{uptime_seconds % 60:02}"
            else:
                snmp_results['sysUpTimeFormatted'] = "Unknown"
        except ValueError:
            snmp_results['sysUpTimeFormatted'] = "Unknown"

        snmp_results['timestamp'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        device.last_query_results = snmp_results
        device.last_query_time = datetime.now()

        # Only try to get interface data if we didn't encounter errors on basic OIDs
        interface_data = []
        if not has_auth_error and not has_timeout_error and device.interface_indexes:
            for idx in map(int, filter(None, device.interface_indexes.split(','))):
                oid = f'1.3.6.1.2.1.2.2.1.2.{idx}'
                result = snmp_query(device, oid)
                if result['success']:
                    interface_data.append({'index': idx, 'name': result['value']})
                else:
                    interface_data.append({'index': idx, 'name': 'Error retrieving interface'})

        db.session.commit()

        return render_template(
            'query_results.html',
            device=device,
            results=snmp_results,
            interface_data=interface_data
        )

    except Exception as e:
        flash(f"Error querying device: {e}", "danger")
        return redirect(url_for('device_routes.index'))


from flask import request, redirect, url_for, flash
from pysnmp.hlapi import setCmd, OctetString, Integer

@bp.route('/set_oid_value/<int:device_id>', methods=['POST'])
def set_oid_value(device_id):
    device = Device.query.get_or_404(device_id)
    oid = request.form.get('oid')
    value = request.form.get('value')

    try:
        # Determine appropriate type (integer or string)
        if value.isdigit():
            result = snmp_set(device, oid, int(value))
        else:
            result = snmp_set(device, oid, value)
            
        if result['success']:
            flash("Value updated successfully.", "success")
        else:
            if result['error_type'] == 'auth':
                flash(f"Authentication error: {result['error']}", "warning")
            elif result['error_type'] == 'timeout':
                flash(f"Device not responding: {result['error']}", "warning")
            else:
                flash(f"SNMP Set failed: {result['error']}", "danger")
    except Exception as e:
        flash(f"Error: {e}", "danger")

    return redirect(url_for('device_routes.query_device', device_id=device_id))
