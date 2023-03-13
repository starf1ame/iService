from sqlalchemy import create_engine
from sqlalchemy import Column, Index, Integer, String, Enum, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship, sessionmaker

import models.conf


def connect():
    info = models.conf.get()
    env = info['services']['db']['environment']

    s = f'''postgresql://{env['POSTGRES_USER']}:{env['POSTGRES_PASSWORD']}@localhost:5432/{env['POSTGRES_DB']}'''
    return create_engine(s)


def get():
    engine = connect()
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    return Session(), engine


Base = declarative_base()

class Binary(Base):
    __tablename__ = 'binary'

    id = Column(Integer)
    path = Column(String, primary_key=True)
    cate = Column(String) # service or framework

    entries = relationship('Entry', backref='binary')


class Entry(Base):
    __tablename__ = 'entry'

    id = Column(Integer, primary_key=True)
    ea = Column(String)
    fname = Column(String)
    caller = Column(String) # Used for framework
    cate = Column(String)   # NSXPC, XPC, or external

    binary_path = Column(String, ForeignKey('binary.path'))


class Sop(Base):
    __tablename__ = 'sop'

    id = Column(Integer)
    loc = Column(String, primary_key=True)
    cate = Column(String)       # oc or c
    service = Column(String)    # Path of the service
    binary = Column(String)     # Binary of service or framework
    name = Column(String)


class InputValidation(Base):
    __tablename__ = 'inputvalidation'

    id = Column(Integer, primary_key=True)
    para = Column(String)
    vid = Column(String)
    service = Column(String)    # Path of the service
    fname = Column(String)
    location = Column(String)


class PermissionBase(Base):
    __tablename__ = 'permissionbase'

    id = Column(Integer, primary_key=True)
    service = Column(String)    # Path of the service
    fname = Column(String)
    location = Column(String)


class ServiceName(Base):
    __tablename__ = 'servicename'

    id = Column(Integer, primary_key=True)
    cate = Column(String)       # XPC or NSXPC
    service = Column(String)    # Path of the service
    name = Column(String)
