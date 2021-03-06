#!/usr/bin/env python3
'''Module for the Catalog app server.'''
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from flask import Flask
from flask_seasurf import SeaSurf

# Define the WSGI application object
app = Flask(__name__)
# Load configuration files
app.config.from_object('default_settings')
app.config.from_envvar('APPLICATION_SETTINGS')

from catalog.models import Base

# Connect to database
engine = create_engine(app.config['SQLALCHEMY_DATABASE_URI'])
Base.metadata.create_all(engine)
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
db_session = DBSession()

# Add CSRF protection using SeaSurf (http://flask-seasurf.readthedocs.io)
csrf = SeaSurf(app)

import catalog.controllers
from catalog.api.controllers import api as api_module
from catalog.oauth.controllers import oauth as oauth_module

# Register blueprints
app.register_blueprint(api_module)
app.register_blueprint(oauth_module)
