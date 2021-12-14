from connections.connection import db
from sqlalchemy import Column,String,Integer,DateTime,Boolean,ForeignKey
import datetime

class Book(db.Model):
    
    __table_args__ = {'schema' : 'Task_db'}
    __table_name__ = 'book'
    
    b_id = Column(Integer, primary_key=True, autoincrement=True)
    b_name = Column(String,nullable=False) 
    b_status = Column(Boolean,nullable=False)
    user_id = Column(Integer,ForeignKey('Task_db.person.id'))