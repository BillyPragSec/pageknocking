""" SQLAlchemy ORM Models.

    Each class specifies a corresponding table and its schema.
"""
import json

from sqlalchemy import Column, ForeignKey, UniqueConstraint
from sqlalchemy.types import Integer, String, Numeric, Text, Boolean
from sqlalchemy.orm import relationship
from sqlalchemy.dialects.mysql import ENUM, DATETIME

import database.globals as global_vars

Base = global_vars.Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, autoincrement=True, primary_key=True)
    username = Column(String(30), nullable=False, unique=True)
    trip_count = Column(Integer, nullable=False, default=0)
    logout = Column(Boolean, nullable=False, default=False)
    banned = Column(Boolean, nullable=False, default=False)
    action_expiry = Column(DATETIME, nullable=True)

    devices = relationship("Device", back_populates="user")
    knocks = relationship("Knock", back_populates="user", uselist=False, cascade="all, delete-orphan")
    logs = relationship("Log", back_populates="user")
    policies = relationship("Policy", back_populates="user")

    def __repr__(self):
        return self.username


class Device(Base):
    __tablename__ = "devices"

    id = Column(Integer, autoincrement=True, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id", onupdate="CASCADE"))
    fingerprint = Column(String(128))
    session_key = Column(Text)
    session_id = Column(Text)
    ip = Column(String(22), nullable=False)  # ::ffff:IPV4
    logout = Column(Boolean, default=False)
    banned = Column(Boolean, default=False)
    action_expiry = Column(DATETIME, nullable=True)
    logout_link = Column(Text, nullable=False, default="")

    user = relationship("User", back_populates="devices")
    logs = relationship("Log", back_populates="device")
    __table_args__ = (
        UniqueConstraint(user_id, fingerprint, name="_device_user_fingerprint_uc"),
    )

    def __repr__(self):
        return f"{self.id} {self.session_id} {self.ip}"


class Knock(Base):
    __tablename__ = "knocks"

    id = Column(Integer, autoincrement=True, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"))    
    _knock_sequence = Column(Text, nullable=True, default=None)
    whitelist = Column(Text, nullable=True, default=None)

    user = relationship("User", back_populates="knocks")
    
    @property
    def knock_sequence(self):
        if self._knock_sequence is None or len(self._knock_sequence) == 0:
            return []
        if '\"' in self._knock_sequence:
            return self._knock_sequence.strip('][').strip('\"').split(', ')
        return self._knock_sequence.strip('][').split(', ')

    @knock_sequence.setter
    def knock_sequence(self, value):
        self._knock_sequence = value

    def __repr__(self):
        return f"{self.id}-{self.user_id}-{self.knock_sequence}"




class Log(Base):
    __tablename__ = "logs"

    user_id = Column(Integer, ForeignKey("users.id"), primary_key=True)
    device_id = Column(Integer, ForeignKey("devices.id"), primary_key=True)
    knock_id = Column(Integer, ForeignKey("knocks.id"), primary_key=True)
    time = Column(DATETIME, nullable=False, primary_key=True)
    trip_count = Column(Integer, nullable=False, default=0)
    path = Column(Text, nullable=True)
    action_taken = Column(String(50), nullable=True)

    user = relationship("User", back_populates="logs")
    device = relationship("Device", back_populates="logs")


class Policy(Base):
    __tablename__ = "policies"

    id = Column(Integer, autoincrement=True, primary_key=True)
    time_threshold = Column(Integer, nullable=False, default=60)
    action = Column(String(50), nullable=False)
    persistence_time = Column(Integer, nullable=False, default=60)
    user_id = Column(Integer, ForeignKey("users.id"))

    user = relationship("User", back_populates="policies")

