#!/usr/bin/env python3

from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, ForeignKey, Integer, String, UniqueConstraint, CheckConstraint
from sqlalchemy.orm import relationship

# Library to encrypt passwords
from passlib.apps import custom_app_context

Base = declarative_base()


class User(Base):
    __tablename__ = 'user'
    id = Column(Integer, primary_key=True)
    email = Column(String, index=True)
    password_hash = Column(String(64))

    def hash_password(self, password):
        self.password_hash = custom_app_context.encrypt(password)

    def verify_password(self, password):
        return custom_app_context.verify(password, self.password_hash)


class Category(Base):
    __tablename__ = 'category'
    id = Column(Integer, primary_key=True)
    name = Column(String, CheckConstraint('name!=""'), nullable=False, unique=True, index=True)

    @property
    def serialize(self):
        return {
            'id': self.id,
            'name': self.name
        }

class Item(Base):
    __tablename__ = 'item'
    id = Column(Integer, primary_key=True)
    name = Column(String, CheckConstraint('name!=""'), nullable=False, index=True)
    description = Column(String)
    category_id = Column(Integer, ForeignKey('category.id'), CheckConstraint('category_id!=""'), nullable=False,)
    category = relationship(Category)
    __table_args__ = (UniqueConstraint('name','category_id'), )

    @property
    def serialize(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
        }

if __name__ == '__main__':
    engine = create_engine('sqlite:///catalog.db')
    Base.metadata.create_all(engine)
