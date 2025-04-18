from typing import List, Tuple, Optional, Union, Dict, Any
from app.models import Device
from pysnmp.hlapi import (
    SnmpEngine, CommunityData, UdpTransportTarget, ContextData,
    ObjectType, ObjectIdentity, getCmd, nextCmd, UsmUserData, setCmd,
    OctetString, Integer,
    usmHMACMD5AuthProtocol, usmHMACSHAAuthProtocol, usmNoAuthProtocol,
    usmDESPrivProtocol, usm3DESEDEPrivProtocol, usmAesCfb128Protocol,
    usmAesCfb192Protocol, usmAesCfb256Protocol, usmNoPrivProtocol
)


AUTH_PROTOCOLS = {
    "MD5": usmHMACMD5AuthProtocol,
    "SHA": usmHMACSHAAuthProtocol,
    None: usmNoAuthProtocol
}

PRIV_PROTOCOLS = {
    "DES": usmDESPrivProtocol,
    "3DES": usm3DESEDEPrivProtocol,
    "AES": usmAesCfb128Protocol,
    "AES128": usmAesCfb128Protocol,
    "AES192": usmAesCfb192Protocol,
    "AES256": usmAesCfb256Protocol,
    None: usmNoPrivProtocol
}

# Common SNMP error messages and their user-friendly interpretations
SNMP_ERROR_MESSAGES = {
    "No SNMP response received before timeout": "SNMP Timeout - Device unreachable or incorrect login credentials",
    "Unknown security name": "Unknown security name - Invalid username",
    "Wrong digest": "Authentication failed - Incorrect auth password or protocol",
    "Decryption error": "Decryption failed - Incorrect privacy password or protocol",
    "Unknown security level": "Invalid security level configuration",
    "Wrong PDU type": "Protocol error - Possible version mismatch",
    "requestID mismatch": "SNMP communication error - Possible network issue",
    "No response available": "No response from device - Check connectivity"
}


def snmp_query(device: Device, oid: str) -> Dict[str, Any]:
    """
    Perform a single SNMP query using the SNMPLogin linked to the device.
    
    Returns a dictionary with:
    - 'value': The query result value (if successful)
    - 'error': Error message (if applicable)
    - 'error_type': Type of error ('auth', 'timeout', 'protocol', 'other')
    - 'success': Boolean indicating success/failure
    """
    login = device.snmp_login
    ip = device.ip_address
    result = {
        'value': None,
        'error': None,
        'error_type': None,
        'success': False
    }

    try:
        if login.version in [1, 2]:
            community = login.community
            errorIndication, errorStatus, errorIndex, varBinds = next(
                getCmd(SnmpEngine(),
                    CommunityData(community, mpModel=0 if login.version == 1 else 1),
                    UdpTransportTarget((ip, 161), timeout=1, retries=0),
                    ContextData(),
                    ObjectType(ObjectIdentity(oid)))
            )
        elif login.version == 3:
            level = login.security_level or "noAuthNoPriv"

            auth_proto = AUTH_PROTOCOLS.get((login.auth_protocol or "").upper(), usmNoAuthProtocol)
            priv_proto = PRIV_PROTOCOLS.get((login.priv_protocol or "").upper(), usmNoPrivProtocol)

            if level == "noAuthNoPriv":
                auth_data = UsmUserData(login.username)
            elif level == "authNoPriv":
                auth_data = UsmUserData(
                    login.username,
                    login.auth_key,
                    authProtocol=auth_proto
                )
            elif level == "authPriv":
                auth_data = UsmUserData(
                    login.username,
                    login.auth_key,
                    login.priv_key,
                    authProtocol=auth_proto,
                    privProtocol=priv_proto
                )
            else:
                result['error'] = "Invalid SNMPv3 security level"
                result['error_type'] = "auth"
                return result

            errorIndication, errorStatus, errorIndex, varBinds = next(
                getCmd(SnmpEngine(),
                    auth_data,
                    UdpTransportTarget((ip, 161), timeout=1, retries=0),
                    ContextData(),
                    ObjectType(ObjectIdentity(oid)))
            )
        else:
            result['error'] = "Unsupported SNMP version"
            result['error_type'] = "protocol"
            return result

        if errorIndication:
            error_str = str(errorIndication)
            
            # Categorize the error
            if "timeout" in error_str.lower():
                result['error_type'] = "timeout"
            elif any(auth_err in error_str.lower() for auth_err in ["security", "auth", "password", "community"]):
                result['error_type'] = "auth"
            else:
                result['error_type'] = "other"
                
            # Provide a user-friendly error message if available
            for error_key, friendly_msg in SNMP_ERROR_MESSAGES.items():
                if error_key.lower() in error_str.lower():
                    result['error'] = friendly_msg
                    break
            else:
                result['error'] = str(errorIndication)
                
            return result
            
        elif errorStatus:
            result['error'] = f'{errorStatus.prettyPrint()} at {errorIndex and varBinds[int(errorIndex) - 1][0] or "?"}'
            result['error_type'] = "protocol"
            return result
        else:
            result['value'] = str(varBinds[0][1])
            result['success'] = True
            return result

    except Exception as e:
        result['error'] = f"SNMP Query Error: {str(e)}"
        result['error_type'] = "other"
        return result


def snmp_walk(device: Device, base_oid: str) -> Dict[str, Any]:
    """
    Perform SNMP walk for a device starting at a given OID.
    
    Returns:
    - 'results': List of tuples (oid, value) if successful
    - 'error': Error message (if applicable)
    - 'error_type': Type of error ('auth', 'timeout', 'protocol', 'other')
    - 'success': Boolean indicating success/failure
    """
    login = device.snmp_login
    ip = device.ip_address
    response = {
        'results': [],
        'error': None,
        'error_type': None, 
        'success': False
    }

    try:
        if login.version in [1, 2]:
            community = login.community
            iterator = nextCmd(
                SnmpEngine(),
                CommunityData(community, mpModel=0 if login.version == 1 else 1),
                UdpTransportTarget((ip, 161)),
                ContextData(),
                ObjectType(ObjectIdentity(base_oid)),
                lexicographicMode=False
            )
        elif login.version == 3:
            level = login.security_level or "noAuthNoPriv"

            auth_proto = AUTH_PROTOCOLS.get((login.auth_protocol or "").upper(), usmNoAuthProtocol)
            priv_proto = PRIV_PROTOCOLS.get((login.priv_protocol or "").upper(), usmNoPrivProtocol)

            if level == "noAuthNoPriv":
                auth_data = UsmUserData(login.username)
            elif level == "authNoPriv":
                auth_data = UsmUserData(
                    login.username,
                    login.auth_key,
                    authProtocol=auth_proto
                )
            elif level == "authPriv":
                auth_data = UsmUserData(
                    login.username,
                    login.auth_key,
                    login.priv_key,
                    authProtocol=auth_proto,
                    privProtocol=priv_proto
                )
            else:
                response['error'] = "Invalid SNMPv3 security level"
                response['error_type'] = "auth"
                return response

            iterator = nextCmd(
                SnmpEngine(),
                auth_data,
                UdpTransportTarget((ip, 161)),
                ContextData(),
                ObjectType(ObjectIdentity(base_oid)),
                lexicographicMode=False
            )
        else:
            response['error'] = "Unsupported SNMP version"
            response['error_type'] = "protocol"
            return response

        for (errorIndication, errorStatus, errorIndex, varBinds) in iterator:
            if errorIndication:
                error_str = str(errorIndication)
                
                # Categorize the error
                if "timeout" in error_str.lower():
                    response['error_type'] = "timeout"
                elif any(auth_err in error_str.lower() for auth_err in ["security", "auth", "password", "community"]):
                    response['error_type'] = "auth"
                else:
                    response['error_type'] = "other"
                    
                # Provide a user-friendly error message if available
                for error_key, friendly_msg in SNMP_ERROR_MESSAGES.items():
                    if error_key.lower() in error_str.lower():
                        response['error'] = friendly_msg
                        break
                else:
                    response['error'] = f"SNMP Walk Error: {errorIndication}"
                    
                return response
            elif errorStatus:
                response['error'] = f"SNMP Walk Error: {errorStatus.prettyPrint()} at {errorIndex and varBinds[int(errorIndex) - 1][0] or '?'}"
                response['error_type'] = "protocol"
                return response
            else:
                for varBind in varBinds:
                    response['results'].append((str(varBind[0]), str(varBind[1])))

        response['success'] = True
        return response

    except Exception as e:
        response['error'] = f"SNMP Walk Error: {str(e)}"
        response['error_type'] = "other"
        return response


def check_snmp_port(device: Device) -> bool:
    """Check if the SNMP port is responsive for the device using sysObjectID."""
    try:
        print(f"Checking SNMP on {device.ip_address}...", end=' ')
        result = snmp_query(device, '1.3.6.1.2.1.1.2.0')  # sysObjectID
        is_responding = result['success']
        print(f"{'Found SNMP device' if is_responding else 'No response'}")
        return is_responding
    except Exception as e:
        print(f"Error checking SNMP port for {device.ip_address}: {e}")
        return False


from pysnmp.hlapi import (
    setCmd, OctetString, Integer, ObjectIdentity, ObjectType,
)


def snmp_set(device: Device, oid: str, value: Union[str, int]) -> Dict[str, Any]:
    """
    Perform an SNMP SET operation on the given OID with the specified value.
    
    Returns:
    - 'success': Boolean indicating success/failure
    - 'error': Error message (if applicable)
    - 'error_type': Type of error ('auth', 'timeout', 'protocol', 'other')
    """
    login = device.snmp_login
    ip = device.ip_address
    response = {
        'success': False,
        'error': None,
        'error_type': None
    }

    try:
        # Determine value type
        if isinstance(value, int) or (isinstance(value, str) and value.isdigit()):
            value_obj = Integer(int(value))
        else:
            value_obj = OctetString(value)

        if login.version in [1, 2]:
            community = login.community
            errorIndication, errorStatus, errorIndex, varBinds = next(
                setCmd(
                    SnmpEngine(),
                    CommunityData(community, mpModel=0 if login.version == 1 else 1),
                    UdpTransportTarget((ip, 161), timeout=1, retries=0),
                    ContextData(),
                    ObjectType(ObjectIdentity(oid), value_obj)
                )
            )
        elif login.version == 3:
            level = login.security_level or "noAuthNoPriv"

            auth_proto = AUTH_PROTOCOLS.get((login.auth_protocol or "").upper(), usmNoAuthProtocol)
            priv_proto = PRIV_PROTOCOLS.get((login.priv_protocol or "").upper(), usmNoPrivProtocol)

            if level == "noAuthNoPriv":
                auth_data = UsmUserData(login.username)
            elif level == "authNoPriv":
                auth_data = UsmUserData(
                    login.username,
                    login.auth_key,
                    authProtocol=auth_proto
                )
            elif level == "authPriv":
                auth_data = UsmUserData(
                    login.username,
                    login.auth_key,
                    login.priv_key,
                    authProtocol=auth_proto,
                    privProtocol=priv_proto
                )
            else:
                response['error'] = "Invalid SNMPv3 security level"
                response['error_type'] = "auth"
                return response

            errorIndication, errorStatus, errorIndex, varBinds = next(
                setCmd(
                    SnmpEngine(),
                    auth_data,
                    UdpTransportTarget((ip, 161), timeout=1, retries=0),
                    ContextData(),
                    ObjectType(ObjectIdentity(oid), value_obj)
                )
            )
        else:
            response['error'] = "Unsupported SNMP version"
            response['error_type'] = "protocol"
            return response

        if errorIndication:
            error_str = str(errorIndication)
            
            # Categorize the error
            if "timeout" in error_str.lower():
                response['error_type'] = "timeout"
            elif any(auth_err in error_str.lower() for auth_err in ["security", "auth", "password", "community"]):
                response['error_type'] = "auth"
            else:
                response['error_type'] = "other"
                
            # Provide a user-friendly error message if available
            for error_key, friendly_msg in SNMP_ERROR_MESSAGES.items():
                if error_key.lower() in error_str.lower():
                    response['error'] = friendly_msg
                    break
            else:
                response['error'] = f"SNMP Set Error: {errorIndication}"
            
            return response
        elif errorStatus:
            response['error'] = f"SNMP Set Error: {errorStatus.prettyPrint()} at {errorIndex and varBinds[int(errorIndex) - 1][0] or '?'}"
            response['error_type'] = "protocol"
            return response

        response['success'] = True
        return response

    except Exception as e:
        response['error'] = f"SNMP Set Error: {str(e)}"
        response['error_type'] = "other"
        return response

