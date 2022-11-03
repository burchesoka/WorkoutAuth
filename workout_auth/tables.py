from datetime import datetime

from sqlalchemy import (
    Column,
    DateTime,
    BigInteger,
    String,
    MetaData,

)
from sqlalchemy.ext.declarative import declarative_base



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
    status = Column(String)
    last_seen = Column(DateTime, default=datetime.utcnow())
