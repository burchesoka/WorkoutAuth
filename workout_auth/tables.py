from datetime import datetime

from sqlalchemy import (
    Column,
    DateTime,
    BigInteger,
    String,
    MetaData,
    ForeignKey,
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship



"""
All time of day in DB is local. Utc time have to be calculated using 'timezone_utc' column.
All datetime is UTC
"""

convention = {
    'all_column_names': lambda constraint, table: '_'.join([
        column.name for column in constraint.columns.values()
    ]),
    'ix': 'ix__%(table_name)s__%(all_column_names)s',
    'uq': 'uq__%(table_name)s__%(all_column_names)s',
    'ck': 'ck__%(table_name)s__%(constraint_name)s',
    'fk': (
        'fk__%(table_name)s__%(all_column_names)s__'
        '%(referred_table_name)s'
    ),
    'pk': 'pk__%(table_name)s'
}

metadata = MetaData(naming_convention=convention)

Base = declarative_base(metadata=metadata)


class User(Base):
    __tablename__ = 'users'

    id = Column(BigInteger, primary_key=True)
    api_id = Column(BigInteger, unique=True, index=True)
    telegram_id = Column(BigInteger, unique=True, index=True, nullable=False)

    email = Column(String, unique=True)
    password_hash = Column(String)

    name = Column(String(100))
    last_seen = Column(DateTime, default=datetime.utcnow())

    refresh_token = relationship('RefreshToken', back_populates='user', uselist=False)


class RefreshToken(Base):
    __tablename__ = 'refresh_tokens'

    user_id = Column(ForeignKey('users.id'), primary_key=True)
    refresh_token = Column(String)

    user = relationship('User', back_populates='refresh_token')
