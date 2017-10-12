#!/usr/bin/env python3

from sqlalchemy import (create_engine, Column, ForeignKey, Integer, String,
                        UniqueConstraint, CheckConstraint)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from hashlib import sha256
from os import urandom
from itsdangerous import (TimedJSONWebSignatureSerializer as Serializer,
                          BadSignature, SignatureExpired)

Base = declarative_base()

# Secret key to create and verify tokens
secret_key = sha256(urandom(1024)).hexdigest()


class User(Base):
    __tablename__ = 'user'
    id = Column(Integer, primary_key=True)
    email = Column(String, CheckConstraint('email!=""'), index=True,
                   unique=True, nullable=False)

    def generate_auth_token(self, expiration=600):
        s = Serializer(secret_key, expires_in=expiration)
        return s.dumps({'id': self.id})

    @staticmethod
    def verify_auth_token(token):
        s = Serializer(secret_key)
        try:
            data = s.loads(token)
        except SignatureExpired:
            return None
        except BadSignature:
            return None
        user_id = data['id']
        return user_id


class Category(Base):
    __tablename__ = 'category'
    id = Column(Integer, primary_key=True)
    name = Column(String, CheckConstraint('name!=""'), nullable=False,
                  unique=True, index=True)

    @property
    def serialize(self):
        return {
            'id': self.id,
            'name': self.name
        }


class Item(Base):
    __tablename__ = 'item'
    id = Column(Integer, primary_key=True)
    name = Column(String, CheckConstraint('name!=""'), nullable=False,
                  index=True)
    description = Column(String)
    image_url = Column(String)
    category_id = Column(Integer, ForeignKey('category.id'),
                         CheckConstraint('category_id!=""'), nullable=False)
    category = relationship(Category)
    user_id = Column(Integer, ForeignKey('user.id'),
                     CheckConstraint('user_id!=""'), nullable=False)
    user = relationship(User)
    __table_args__ = (UniqueConstraint('name', 'category_id'), )

    @property
    def serialize(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'image_url': self.image_url
        }


if __name__ == '__main__':
    engine = create_engine('sqlite:///catalog.db')
    Base.metadata.create_all(engine)
