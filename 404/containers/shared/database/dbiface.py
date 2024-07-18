""" Database-interfacing code.

    For the rest of our code base, this should be the default point of contact for all database-related calls.
"""
from contextlib import contextmanager
import csv
from datetime import datetime, timedelta
import json
import os
import time

import pytz
from sqlalchemy import create_engine, exc, literal

import database.globals as global_vars
from database.models import (
    User,
    Device,
    Knock,
    Log,
    Policy,
)
from utils.enums.actions_enum import ActionsEnum
from utils.enums.components_enum import ComponentsEnum
from utils.enums.logs_enum import LogsEnum
from utils.enums.db_err_enum import DBErrorsEnum
from utils.proj_utils import load_config, init_logger

Base = global_vars.Base
engine = global_vars.engine
Session = global_vars.Session
APP_CONFIG = load_config()
TIMEZONE = APP_CONFIG["TIMEZONE"]
LOGGER = init_logger(__name__, LogsEnum.SYSTEM)
DB_LOG = LOGGER.init_log_metadata(
    {
        "component_type": ComponentsEnum.DB,
    }
)

###################################################
# Connection and Session Management
###################################################


def connect(conn_string, db):
    """Sets up the database connection through SQLAlchemy.

    Args:
        conn_string (str): string without database
        db (str): database name
    """

    global engine

    try:
        engine = create_engine(f"{conn_string}/{db}", pool_recycle=3600)
    except Exception as e:
        print(e)
        engine = create_engine(conn_string, pool_recycle=3600)
        engine.execute(f"CREATE DATABASE IF NOT EXISTS {db};")
        engine.execute(f"USE {db}")

    Session.configure(bind=engine)


def create_tables():
    """Creates the database tables if they don't already exist."""
    Base.metadata.create_all(engine)


def create_session():
    """Creates and returns a Session instance.

    Returns:
        sqlalchemy.orm.Session: sqlalchemy Session
    """
    return Session()


def close_session(session):
    """Commits a session and closes it.

    Should be called before exiting any one request or response method.
    """
    session.commit()
    session.close()


@contextmanager
def managed_session():
    """A context manager that yields a sqlalchemy Session and closes it
    to commit transactions.

    Yields:
        sqlaclhemy.orm.Session: sqlalchemy Session
    """
    session = create_session()
    try:
        yield session
    finally:
        close_session(session)


def init(conn_string, db):
    """Initializes the database connection and creates the tables.

    Args:
        conn_string (str): string without database
        db (str): database name
    """
    time.sleep(10)  # wait a little before attempting to connect
    try:
        connect(conn_string, db)
        create_tables()
        LOGGER.info(DB_LOG, "Created tables.")
    except exc.SQLAlchemyError as e:
        LOGGER.info(DB_LOG, f"Exception in connecting to the database: {e}.")


###################################################
# User and Device Info
###################################################


def create_new_user(session, username):
    """Creates a new User entry.

    Args:
        session (sqlalchemy.orm.Session): sqlalchemy Session
        username (str): username

    Returns:
        database.models.User: User object
    """
    user = get_user_by_name(session, username)
    if user is not None:
        print("User already exists")
        return DBErrorsEnum.USER_EXISTS
    user = User(username=username)
    add_default_policies(user)
    add_default_knocking_sequence(user)
    session.add(user)
    return user


def create_new_device(session, user, device_fingerprint, ip=None):
    """Creates a new Device associated with the user username.


    Args:
        session (sqlalchemy.orm.Session): sqlalchemy Session
        device_fingerprint (str): device fingerprint
        username (str): username
        ip (str): client ip

    Returns:
        database.models.Device: Device object
    """
    if ip is None:
        ip = device_fingerprint
    if user is None:
        return DBErrorsEnum.USER_NOT_FOUND
    device = (
        session.query(Device)
        .filter_by(user=user, fingerprint=device_fingerprint)
        .first()
    )
    if device is None:
        device = Device(
            user=user,
            fingerprint=device_fingerprint,
            session_id="",
            session_key="",
            ip=ip,
        )
        session.add(device)
    return device


def get_user_by_name(session, username):
    """Retrieves a User by their username.

    Args:
        session (sqlalchemy.orm.Session): sqlalchemy Session
        username (str): username

    Returns:
        database.models.User: User object
    """
    user = session.query(User).filter_by(username=username).first()
    return user


def get_device(session, device_fingerprint=None, ssid=None, user_id=None):
    """Retrieves a Device by its fingerprint, session id, and/or user_id.

    Args:
        session (sqlalchemy.orm.Session): sqlalchemy Session
        device_fingerprint (str): device fingerprint
        ssid (str): application session id
        user_id (str): User id

    Returns:
        database.models.Device: Device object
    """
    if device_fingerprint is None and ssid is None and user_id is None:
        #print('Device fingerprint or ssid or user_id are none')
        #print('Device fingerprint: ', device_fingerprint)
        #print('ssid: ', ssid)
        #print('user_id: ', user_id)
        return None
    if device_fingerprint is not None and ssid is not None:
        #print('Device fingerprint and ssid are not none')
        #print('Device fingerprint: ', device_fingerprint)
        #print('ssid: ', ssid)
        #print('user_id: ', user_id)
        return (
            session.query(Device)
            .filter_by(fingerprint=device_fingerprint, session_id=ssid)
            .first()
        )
    if device_fingerprint is not None and user_id is not None:
        #print('Device fingerprint and ser_id are not none')
        #print('Device fingerprint: ', device_fingerprint)
        #print('ssid: ', ssid)
        #print('user_id: ', user_id)
        return (
            session.query(Device)
            .filter_by(fingerprint=device_fingerprint, user_id=user_id)
            .first()
        )
    if device_fingerprint is None:
        #print('Device fingerprint is none')
        #print('Device fingerprint: ', device_fingerprint)
        #print('ssid: ', ssid)
        #print('user_id: ', user_id)
        return session.query(Device).filter_by(session_id=ssid).first()
    if ssid is None:
        #print('ssid is none')
        #print('Device fingerprint: ', device_fingerprint)
        #print('ssid: ', ssid)
        #print('user_id: ', user_id)
        return session.query(Device).filter_by(fingerprint=device_fingerprint).first()

def get_knock_from_user(session, user):
    """Retrieves the Page Knocking sequence from a User.
    If there is no sequence object, a new one is created.

    Args:
        session (sqlalchemy.orm.Session): sqlalchemy Session
        user (database.models.User): User object

    Returns:
        database.models.Knock: Knock object
    """
    if user.knocks is None:
        user.knocks = Knock(id=user.id)
        session.add(user)
    return user.knocks


###################################################
# Action Enforcement
#   NOTE: these functions expect the queried
#           user or device to already exist
###################################################


def set_logout_user(user, val):
    """Marks that a User should or should not be logged out.

    Args:
        user (database.models.User): User object
        val (bool): whether the User should be logged out
    """
    user.logout = val


def set_logout_device(device, val):
    """Marks that a Device should or should not be logged out.

    Args:
        device (database.models.Device): Device object
        val (bool): whether the User should be logged out
    """
    device.logout = val


def ban_user(user, expiry):
    """Marks that a User should be banned for some duration.

    Args:
        user (database.models.User): User object
        expiry (int): duration (number of seconds)
    """
    user.banned = True
    if expiry is not None:
        user.action_expiry = datetime.now(tz=pytz.timezone(TIMEZONE)) + timedelta(
            seconds=expiry
        )


def ban_device(device, expiry):
    """Marks that a Device should be banned for some duration.

    Args:
        device (database.models.Device): Device object
        expiry (int): duration (number of seconds)
    """
    device.banned = True
    if expiry is not None:
        device.action_expiry = datetime.now(tz=pytz.timezone(TIMEZONE)) + timedelta(
            seconds=expiry
        )


def is_logout_user(user):
    """Checks whether the User should be logged out.

    Args:
        user (database.models.User): User object

    Returns:
        bool: whether the User should be logged out
    """
    return user.logout


def is_logout_device(device):
    """Checks whether the Device should be logged out.

    Args:
        device (database.models.Device): Device object

    Returns:
        bool: whether the Device should be logged out
    """
    return device.logout


def is_ban_user(user):
    """Checks whether the User should be banned.

    Args:
        user (database.models.User): User object

    Returns:
        bool: whether the User should be banned
    """
    if user.banned == True:
        if user.action_expiry is not None and user.action_expiry < datetime.now(
            tz=pytz.timezone(TIMEZONE)
        ):
            user.action_expiry = None
            user.banned = False
    return user.banned


def is_ban_device(device):
    """Checks whether the Device should be banned.

    Args:
        device (database.models.Device): Device object

    Returns:
        bool: whether the Device should be banned
    """
    if device.banned == True:
        if device.action_expiry is not None and device.action_expiry < datetime.now(
            tz=pytz.timezone(TIMEZONE)
        ):
            device.action_expiry = None
            device.banned = False
    return device.banned


def add_default_knocking_sequence(user):
    
    LOGGER.info(DB_LOG, f"Adding default knocking sequence for user {user}.")

    address = os.environ["PROXY_ADDRESS"]
    default_knocking_sequence_csv = os.environ["DEFAULT_KNOCKING_SEQUENCE"]
    rows = []
    knocks = []
    with open(default_knocking_sequence_csv) as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            rows.append(row)

    for row in rows:
        if str(user) in row['user']:
            element = Knock(
                user=user,
                user_id = row['user_id'],
                knock_sequence = row['knock_sequence'],
                whitelist = row['whitelist'],
            )
            knocks.append(element)

    #added = False
    #if user is not None:
    #    for element in knocks:
    #       if element not in user.knocks:
    #            user.knocks.append(element)
    #            added = True
    return True
