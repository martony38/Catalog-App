#!/usr/bin/env python3
'''Default configuration file for Catalog App'''
from os import environ, path

# Define the application directory
BASE_DIR = path.abspath(path.dirname(__file__))

# Define the database
SQLALCHEMY_DATABASE_URI = 'sqlite:///' + path.join(BASE_DIR, 'catalog.db')

# Folder where item images will be uploaded (wil be a subfolder of static/).
UPLOAD_FOLDER = 'img/uploads/'

# Item default image.  Place this image in the UPLOAD_FOLDER defined above.
DEFAULT_IMAGE = 'tiger-2535888_640.jpg'

# File extensions allowed for upload.
ALLOWED_EXTENSIONS = {'jpg', 'png', 'jpeg', 'gif'}

# Enable debug mode
DEBUG = True

# For development and testing purposes, enable oauth2 to work without ssl so
# that the fetch_token method from requests_oauthlib do not raise:
# oauthlib.oauth2.rfc6749.errors.InsecureTransportError.
environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

# Max request size (file upload) in bytes
MAX_CONTENT_LENGTH = 5 * (1024 * 1024)

# Rate limiting options
MAX_REQUESTS = 60
TIME_SPAN = 60  # seconds
BUCKET_INTERVAL = 5  # seconds
