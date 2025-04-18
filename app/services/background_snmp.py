from app import db
from app.models import Device, CounterHistory
from datetime import datetime
import threading
import time
from app.services.snmp_utils import snmp_query

def update_device_history(app):
    with app.app_context():
        while True:
            try:
                current_time = datetime.utcnow()
                devices = Device.query.all()

                for device in devices:
                    if not device.interface_indexes:
                        continue

                    indexes = [idx.strip() for idx in device.interface_indexes.split(',') if idx.strip().isdigit()]
                    
                    for index in indexes:
                        in_oid = f"1.3.6.1.2.1.2.2.1.10.{index}"
                        out_oid = f"1.3.6.1.2.1.2.2.1.16.{index}"

                        in_result = snmp_query(device, in_oid)
                        out_result = snmp_query(device, out_oid)

                        # Skip if either query failed or returned non-numeric value
                        if not (in_result['success'] and out_result['success']):
                            if in_result.get('error_type') == 'timeout' or out_result.get('error_type') == 'timeout':
                                print(f"[WARN] Device {device.ip_address} not responding to SNMP")
                            elif in_result.get('error_type') == 'auth' or out_result.get('error_type') == 'auth':
                                print(f"[WARN] Authentication error for device {device.ip_address}")
                            continue
                            
                        in_octets = in_result['value'] 
                        out_octets = out_result['value']
                        
                        # Verify values are numeric
                        if not (str(in_octets).isdigit() and str(out_octets).isdigit()):
                            print(f"[WARN] Non-numeric counter values for device {device.ip_address}, interface {index}")
                            continue

                        counter_history = CounterHistory(
                            device_id=device.id,
                            in_octets=int(in_octets),
                            out_octets=int(out_octets),
                            interface_index=int(index),
                            timestamp=current_time
                        )
                        db.session.add(counter_history)

                        # Keep only last 30 entries per interface
                        count = CounterHistory.query.filter_by(
                            device_id=device.id,
                            interface_index=index
                        ).count()

                        if count > 30:
                            oldest = CounterHistory.query.filter_by(
                                device_id=device.id,
                                interface_index=index
                            ).order_by(CounterHistory.timestamp.asc()).first()
                            if oldest:
                                db.session.delete(oldest)

                db.session.commit()

            except Exception as e:
                print(f"[ERROR] SNMP polling failed: {e}")
                db.session.rollback()

            time.sleep(10)

def start_background_snmp_polling(app):
    thread = threading.Thread(target=update_device_history, args=(app,))
    thread.daemon = True
    thread.start()
