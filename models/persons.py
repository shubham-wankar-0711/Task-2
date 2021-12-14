from connections.connection import db
from sqlalchemy.orm import relationship
from sqlalchemy import Column,Integer,String,Boolean

class Person(db.Model):
    
    __table_args__ = {'schema' : 'Task_db'}
    __table_name__ = 'person'
    
    id = Column(Integer, primary_key=True, autoincrement=True, unique=True)
    public_id = Column(String, nullable=False)
    name = Column(String, nullable=False)
    password = Column(String, nullable=False)
    admin = Column(Boolean,nullable=False)
    book = relationship("Book",backref="owner",lazy='dynamic')