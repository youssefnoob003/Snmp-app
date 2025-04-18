from app import db, models_engine
from sqlalchemy import text
from datetime import datetime

class SNMPLogin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    version = db.Column(db.Integer, nullable=False)
    security_level = db.Column(db.Integer, nullable=True)
    community = db.Column(db.String(50), nullable=True)
    username = db.Column(db.String(50), nullable=True)
    auth_protocol = db.Column(db.String(10), nullable=True)
    auth_key = db.Column(db.String(100), nullable=True)
    priv_protocol = db.Column(db.String(10), nullable=True)
    priv_key = db.Column(db.String(100), nullable=True)

    devices = db.relationship('Device', back_populates='snmp_login', lazy=True)

    def __repr__(self):
        return f'<SNMPLogin {self.version} {self.username}>'

    def __init__(self, version, username=None, auth_protocol=None, auth_key=None, priv_protocol=None, priv_key=None, security_level=None, community=None):
        if version == 1:
            self.community = community
        elif version == 2:
            self.community = community
        elif version == 3:
            self.username = username
            self.auth_protocol = auth_protocol
            self.auth_key = auth_key
            self.priv_protocol = priv_protocol
            self.priv_key = priv_key
            self.security_level = security_level
        
        self.version = version


class Device(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(15), nullable=False)
    model = db.Column(db.String(100))
    interface_indexes = db.Column(db.String(255), nullable=True)
    os = db.Column(db.String(50), nullable=True)

    snmp_login_id = db.Column(db.Integer, db.ForeignKey('snmp_login.id'), nullable=False)
    
    snmp_login = db.relationship('SNMPLogin', back_populates='devices')

    def get_first_int(self):
        return self.interface_indexes.split(',')[0] if self.interface_indexes else None

    def __init__(self, ip_address, os, snmp_login):
        self.ip_address = ip_address
        self.os = os
        self.snmp_login = snmp_login

    def __repr__(self):
        return f'<Device {self.ip_address} {self.os}>'

    @staticmethod
    def get_model_from_oid(cls, oid):
        oid = '.' + oid
        with models_engine.connect() as connection:
            result = connection.execute(
                text("SELECT name FROM devices WHERE oid = :oid"), {'oid': oid}
            ).fetchone()
        if result:
            return result[0]
        return None


class CounterHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey('device.id'), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    in_octets = db.Column(db.BigInteger, nullable=False)
    out_octets = db.Column(db.BigInteger, nullable=False)
    interface_index = db.Column(db.BigInteger, nullable=False)

    device = db.relationship('Device', backref=db.backref('counter_history', lazy='dynamic'))

    def __repr__(self):
        return f'<CounterHistory {self.device_id} {self.timestamp}>'