#!/usr/bin/env python3
'''Catalog app helper methods.'''
from os import path
from functools import wraps

from werkzeug.utils import secure_filename
from flask import jsonify, flash, redirect, url_for, session, g

from app import app, db_session
from models import Item


def debug():
    '''Launch the debugger if debug mode is enabled.'''
    assert app.debug is False


def allowed_file(filename):
    '''Check file extension.'''
    return ('.' in filename and
            filename.rsplit('.', 1)[1].lower() in
            app.config['ALLOWED_EXTENSIONS'])


def login_required(f):
    '''Redirect users that are not logged in.'''
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login first', 'alert-primary')
            return redirect(url_for('show_login'))
        return f(*args, **kwargs)
    return decorated_function


def clear_session():
    if 'provider' in session:
        del session['provider']
    if 'user_id' in session:
        del session['user_id']
    if 'email' in session:
        del session['email']
    if 'credentials' in session:
        del session['credentials']
    if 'facebook_id' in session:
        del session['facebook_id']
    if 'access_token' in session:
        del session['access_token']
    if 'resource_owner_key' in session:
        del session['resource_owner_key']
    if 'resource_owner_secret' in session:
        del session['resource_owner_secret']
    if 'oauth_state' in session:
        del session['oauth_state']
    if '_csrf_token' in session:
        del session['_csrf_token']


def error_message(ressource, ressource_name, request_type):
    '''Return a ressource not found message for html and api endpoints.'''
    error_message = "no {0} '{1}' found".format(ressource, ressource_name)
    if request_type == 'api':
        return (jsonify(Error=error_message), 404)
    elif request_type == 'browser':
        return 'Error: ' + error_message


def upload_file(file):
    '''Save file and return its url.'''
    filename = secure_filename(file.filename)
    file.save(path.join('./static/' + app.config['UPLOAD_FOLDER'], filename))
    return url_for('static', filename=(app.config['UPLOAD_FOLDER'] + filename))


def create_item(user_id):
    '''Save a new item to database.'''
    if g.get('params'):

        if g.params.get('image'):
            img_url = upload_file(g.params['image'])

            # If no image is uploaded, add a default image
        else:
            img_url = url_for('static', filename=(app.config['UPLOAD_FOLDER'] +
                                                  app.config['DEFAULT_IMAGE']))

        item = Item(name=g.params.get('name'),
                    description=g.params.get('description'),
                    category_id=g.params.get('category_id'),
                    user_id=user_id, image_url=img_url)
        db_session.add(item)
        db_session.commit()
        return item


def update_item(item):
    '''Update an existing item in the database.'''
    if g.get('params'):
        if g.params.get('category_id'):
            item.category_id = g.params['category_id']
        if g.params.get('name'):
            item.name = g.params['name']
        if g.params.get('description'):
            item.description = g.params['description']
        if g.params.get('image'):
            item.image_url = upload_file(g.params['image'])
        db_session.add(item)
        db_session.commit()
