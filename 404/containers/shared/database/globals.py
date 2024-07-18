from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

Base = declarative_base()
engine = None
Session = sessionmaker(
    autoflush=True, expire_on_commit=True
)  # for updating log without refetching
