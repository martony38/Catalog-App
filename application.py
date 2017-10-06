#!/usr/bin/env python3
import json

from requests import PreparedRequest
from requests_oauthlib import OAuth1Session, OAuth2Session

from flask_seasurf import SeaSurf

from sqlalchemy import create_engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker
from models import Base, User, Item, Category

from flask import (Flask, request, render_template, redirect, url_for, flash,
                   jsonify, g, session)

from hashlib import sha256
from os import urandom, environ

from functools import wraps

# Connect to database
engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
db_session = DBSession()

# For development and testing purposes, enable oauth2 to work without ssl so
# that the fetch_token method from requests_oauthlib do not raise:
# oauthlib.oauth2.rfc6749.errors.InsecureTransportError
environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

app = Flask(__name__)

# Add CSRF protection using SeaSurf (http://flask-seasurf.readthedocs.io).
csrf = SeaSurf(app)


def debug():
    assert app.debug is False


def verify_token(f):
    '''Check API authorization token.'''
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method in ['POST', 'PUT', 'DELETE']:
            user_id = User.verify_auth_token(request.headers['auth_token'])
            if user_id:
                user = db_session.query(User).get(user_id)
                if user:
                    g.user = user
                    return f(*args, **kwargs)
            return jsonify(Error='wrong authorization token')
        else:
            return f(*args, **kwargs)
    return decorated_function


def login_required(f):
    '''Check if user is logged in and if not redirect user.'''
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login first', 'alert-primary')
            return redirect(url_for('show_login'))
        return f(*args, **kwargs)
    return decorated_function


def redirect_user_if_already_logged_in(f):
    '''Check if user is already logged in and if so redirect user.'''
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' in session:
            flash('You are already logged in', 'alert-primary')
            return redirect(url_for('show_catalog'))
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


def get_oauth_credentials(provider):
    ''' Extract OAuth credentials from file.'''
    with open('oauth_credentials.json') as secrets_file:
        secret_json = json.load(secrets_file)[provider]
    if provider == 'twitter':
        client_id = secret_json['consumer_key']
        client_secret = secret_json['consumer_secret']
        redirect_uri = url_for('oauth1_callback', provider=provider,
                               _external=True)
    else:
        client_id = secret_json['client_id']
        client_secret = secret_json['client_secret']
        redirect_uri = url_for('oauth2_callback', provider=provider,
                               _external=True)
    return client_id, client_secret, redirect_uri


def login_or_register_user(provider, email):
    '''Check if user exists, if not create new user and log them in'''
    user = db_session.query(User).filter_by(email=email).first()
    if not user:
        user = User(email=email)
        db_session.add(user)
        db_session.commit()
    session['provider'] = provider
    session['user_id'] = user.id
    session['email'] = user.email


def error_message(model, model_name, request_type):
    error_message = "no {0} '{1}' found".format(model, model_name)
    if request_type == 'api':
        return (jsonify(Error=error_message), 404)
    elif request_type == 'browser':
        return 'Error: ' + error_message


def create_item(category_id, name, description, user_id):
    item = Item(name=name, description=description, category_id=category_id,
                user_id=user_id)
    db_session.add(item)
    db_session.commit()
    return item


def update_item(item, category_id, name, description):
    item.name = name
    item.description = description
    item.category_id = category_id
    db_session.add(item)
    db_session.commit()


def get_category_json(category):
    '''Returns a json with all items from a category.'''
    items = db_session.query(Item).filter_by(category_id=category.id).all()
    category_json = category.serialize
    category_json['items'] = [item.serialize for item in items]
    return category_json


# Get a token for a user with login credentials
@app.route('/token', methods=['GET'])
@login_required
def get_api_auth_token():
    user = db_session.query(User).get(session['user_id'])
    token = user.generate_auth_token()
    return render_template('api_token.html', token=token.decode('ascii'),)


@app.route('/login', methods=['GET'])
def show_login():
    return render_template('login.html')


@app.route('/logout')
def disconnect():
    clear_session()
    flash('You have been logged out', 'alert-success')
    return redirect(url_for('show_catalog'))


@app.route('/oauth2login/<provider>')
@redirect_user_if_already_logged_in
def oauth2_login(provider):
    # Configure variables for OAuth.
    client_id, client_secret, redirect_uri = get_oauth_credentials(provider)

    if provider == 'google':
        scope = 'https://www.googleapis.com/auth/userinfo.email'
        auth_base_url = 'https://accounts.google.com/o/oauth2/v2/auth'

    elif provider == 'github':
        scope = 'user:email'
        auth_base_url = 'https://github.com/login/oauth/authorize'

    elif provider == 'facebook':
        scope = 'email'
        auth_base_url = 'https://www.facebook.com/v2.10/dialog/oauth'

    elif provider == 'linkedin':
        scope = None
        auth_base_url = 'https://www.linkedin.com/oauth/v2/authorization'

    else:
        flash('You can not login with this provider: {}'.format(provider),
              'alert-danger')
        return redirect(url_for('show_login'))

    oauth = OAuth2Session(client_id, redirect_uri=redirect_uri, scope=scope)
    auth_url, state = oauth.authorization_url(auth_base_url)
    session['oauth_state'] = state
    return redirect(auth_url)


@app.route('/oauth2callback/<provider>')
@redirect_user_if_already_logged_in
def oauth2_callback(provider):
    # Get credentials for OAuth.
    client_id, client_secret, redirect_uri = get_oauth_credentials(provider)
    payload = {}

    if provider == 'google':
        token_url = 'https://www.googleapis.com/oauth2/v4/token'
        protected_url = 'https://www.googleapis.com/oauth2/v1/userinfo'

    elif provider == 'github':
        token_url = 'https://github.com/login/oauth/access_token'
        protected_url = 'https://api.github.com/user/emails'

    elif provider == 'facebook':
        token_url = 'https://graph.facebook.com/v2.10/oauth/access_token'
        protected_url = 'https://graph.facebook.com/v2.10/me'
        payload['fields'] = 'email'

    elif provider == 'linkedin':
        token_url = 'https://www.linkedin.com/oauth/v2/accessToken'
        protected_url = 'https://api.linkedin.com/v1/people/~:(email-address)'
        payload['format'] = 'json'

    # Flash error message and redirect user if an unknown provider is used.
    else:
        flash('You can not login with this provider: {}'.format(provider),
              'alert-danger')
        return redirect(url_for('show_login'))

    oauth = OAuth2Session(client_id, state=session['oauth_state'],
                          redirect_uri=redirect_uri)
    try:
        # Fetch the access token
        oauth.fetch_token(token_url, client_secret=client_secret,
                          authorization_response=request.url)

        # Fetch protected user info.
        r = oauth.get(protected_url, params=payload)

        # Fetch the user email from provider response.
        if provider == 'linkedin':
            email = r.json()['emailAddress']
        elif provider == 'github':
            for email_item in r.json():
                if email_item['primary'] is True:
                    email = email_item['email']
        else:
            email = r.json()['email']
    except:
        # If either access token or user info are not obtained from OAuth
        # provider, flash error message and redirect to login page.
        flash('Error: could not obtain your info from {}'.format(provider),
              'alert-danger')
        return redirect(url_for('show_login'))

    login_or_register_user(provider, email)
    return redirect(url_for('show_catalog'))


@app.route('/oauth1login/<provider>')
@redirect_user_if_already_logged_in
def oauth1_login(provider):
    # Create a state token to prevent request forgery.
    # Store it in session for later validation.
    state = sha256(urandom(1024)).hexdigest()
    session['oauth_state'] = state

    # Get credentials for OAuth.
    client_key, client_secret, redirect_uri = get_oauth_credentials(provider)

    # Add state parameter to callback uri
    payload = {'state': state}
    callback_req = PreparedRequest()
    callback_req.prepare_url(redirect_uri, payload)
    callback_uri = callback_req.url

    if provider == 'twitter':
        scope = 'https://www.googleapis.com/auth/userinfo.email'
        auth_base_url = 'https://accounts.google.com/o/oauth2/v2/auth'
        twitter = OAuth1Session(client_key, client_secret=client_secret,
                                callback_uri=callback_uri)

        # First step, fetch the request token.
        request_token_url = 'https://api.twitter.com/oauth/request_token'
        credentials = twitter.fetch_request_token(request_token_url)
        if credentials.get('oauth_callback_confirmed') == 'true':
            session['resource_owner_key'] = credentials.get('oauth_token')
            session['resource_owner_secret'] = credentials.get(
                'oauth_token_secret')

            # Redirect the user
            auth_base_url = 'https://api.twitter.com/oauth/authorize'
            auth_url = twitter.authorization_url(auth_base_url)
            return redirect(auth_url)
        else:
            flash('Error while requesting token to Twitter', 'alert-danger')
            return redirect(url_for('show_login'))

    else:
        flash('You can not login with this provider: {}'.format(provider),
              'alert-danger')
        return redirect(url_for('show_login'))


@app.route('/oauth1callback/<provider>')
@redirect_user_if_already_logged_in
def oauth1_callback(provider):
    # Ensure that the request is not a forgery and that the user sending
    # this connect request is the expected user.
    if request.args.get('state') != session['oauth_state']:
        flash('Error: invalid state parameter', 'alert-danger')
        return redirect(url_for('show_login'))

    # Get credentials for OAuth.
    client_key, client_secret, redirect_uri = get_oauth_credentials(provider)

    if provider == 'twitter':
        # Verify that the token matches the request token received
        # in the first step of the flow.
        if request.args.get('oauth_token') == session['resource_owner_key']:
            # Convert the request token to an access token.
            access_token_url = 'https://api.twitter.com/oauth/access_token'
            resource_owner_key = session['resource_owner_key']
            resource_owner_sec = session['resource_owner_secret']
            verifier = request.args.get('oauth_verifier')
            twitter = OAuth1Session(client_key, client_secret=client_secret,
                                    resource_owner_key=resource_owner_key,
                                    resource_owner_secret=resource_owner_sec,
                                    verifier=verifier)
            try:
                credentials = twitter.fetch_access_token(access_token_url)
                resource_owner_key = credentials.get('oauth_token')
                resource_owner_sec = credentials.get('oauth_token_secret')
            except:
                flash('Error: could not get access token', 'alert-danger')
                return redirect(url_for('show_login'))

            # Set up OAuth to Access user info.
            protected_url = ('https://api.twitter.com/1.1/account/'
                             'verify_credentials.json')
            payload = {'include_email': 'true'}
            twitter = OAuth1Session(client_key, client_secret=client_secret,
                                    resource_owner_key=resource_owner_key,
                                    resource_owner_secret=resource_owner_sec)

            # Fetch the user email from provider.
            try:
                r = twitter.get(protected_url, params=payload)
                email = r.json()['email']
            except:
                # If no email is obtained from OAuth provider, flash error
                # message and redirect to login page.
                flash('Error: could not obtain email from {}'.format(provider),
                      'alert-danger')
                return redirect(url_for('show_login'))
        else:
            flash('Error: no token or wrong token received from provider',
                  'alert-danger')
            return redirect(url_for('show_login'))

    else:
        flash('You can not login with this provider: {}'.format(provider),
              'alert-danger')
        return redirect(url_for('show_login'))

    login_or_register_user(provider, email)
    return redirect(url_for('show_catalog'))


@app.route('/')
@app.route('/catalog', methods=['GET'])
def show_catalog():
    '''Display the catalog page'''
    categories = db_session.query(Category).order_by('name').all()
    latest_items = (db_session.query(Item)
                    .order_by(Item.id.desc()).limit(9).all())
    return render_template('catalog.html',
                           categories=categories,
                           latest_items=latest_items)


@app.route('/catalog/<category_name>', methods=['GET'])
def show_category(category_name):
    '''Try to find a category in the database whose name matches the uri.
       If a match is found, display the corresponding category page.
       If no category is found, flash an error message and redirect to the
       catalog page.'''
    category = (db_session.query(Category)
                .filter_by(name=category_name).one_or_none())
    if category:
        items = (db_session.query(Item).filter_by(category_id=category.id)
                 .order_by('name').all())
        categories = db_session.query(Category).order_by('name').all()
        return render_template('show_category.html',
                               categories=categories,
                               category=category,
                               items=items)
    else:
        flash(error_message('category', category_name, 'browser'),
              'alert-danger')
        return redirect(url_for('show_catalog'))


@app.route('/catalog/<category_name>/<item_name>', methods=['GET'])
def show_item(category_name, item_name):
    '''Try to find a item in the database whose name and category name match
       the uri. If a match is found, display the corresponding item page.
       If no category or item is found, flash an error message and redirect
       to the catalog or category page, respectively.'''
    category = (db_session.query(Category)
                .filter_by(name=category_name).one_or_none())
    if category:
        item = (db_session.query(Item)
                .filter_by(name=item_name, category_id=category.id)
                .one_or_none())
        if item:
            categories = db_session.query(Category).order_by('name').all()
            return render_template('show_item.html',
                                   categories=categories,
                                   item=item)
        else:
            flash(error_message('item', item_name, 'browser'), 'alert-danger')
            return redirect(url_for('show_category',
                                    category_name=category.name))
    else:
        flash(error_message('category', category_name, 'browser'),
              'alert-danger')
        return redirect(url_for('show_catalog'))


@app.route('/catalog/new', methods=['GET', 'POST'])
@login_required
def create_new_item():
    '''Display the page to create a new item for GET requests.
       In case of POST requests, try to add a new item to the database
       with the  values passed in the form fields. If item is successfully
       added to the database, flash success message and redirect to the
       item category page. If not, rollback the changes, flash an error
       message, and display the page to create a new item'''
    if request.method == 'POST':
        category = db_session.query(Category).get(request.form['category_id'])
        if category:
            try:
                create_item(category.id,
                            request.form['name'],
                            request.form['description'],
                            session['user_id'])
                flash('item successfully created', 'alert-success')
                return redirect(url_for('show_category',
                                        category_name=category.name))
            except IntegrityError as e:
                db_session.rollback()
                flash('Item not created due to error: ' + e.args[0],
                      'alert-danger')
        else:
            flash(error_message('category with id ',
                                request.form['category_id'],
                                'browser'), 'alert-danger')
    categories = db_session.query(Category).order_by('name').all()
    return render_template('create_new_item.html', categories=categories)


@app.route('/catalog/<category_name>/<item_name>/edit',
           methods=['GET', 'POST'])
@login_required
def edit_item(category_name, item_name):
    '''Try to find a item in the database whose name and category name match
       the uri. If a match is found, display the page to edit this item for
       a GET request. In case of PUT requests, try to update item in the
       database with the  values passed in the form fields. If item is
       successfully updated, flash a success message and redirect to the
       item category page. If not, rollback the changes, flash an error
       message, and display the page to edit this item. If no category or
       item is found, flash an error message and redirect to the catalog
       or category page, respectively.'''
    category = (db_session.query(Category)
                .filter_by(name=category_name).one_or_none())
    if category:
        item = (db_session.query(Item)
                .filter_by(name=item_name, category_id=category.id)
                .one_or_none())
        if item:
            if session['user_id'] != item.user_id:
                flash('You are not authorized to edit this item',
                      'alert-danger')
                return redirect(url_for('show_item',
                                        category_name=category.name,
                                        item_name=item.name))
            if request.method == 'GET':
                categories = db_session.query(Category).order_by('name').all()
                return render_template('edit_item.html', item=item,
                                       categories=categories)
            elif request.method == 'POST':
                try:
                    update_item(item, request.form['category_id'],
                                request.form['name'],
                                request.form['description'])
                    flash('item successfully edited', 'alert-success')
                    return redirect(url_for('show_category',
                                            category_name=item.category.name))
                except IntegrityError as e:
                    db_session.rollback()
                    flash('Item not edited due to error: ' + e.args[0],
                          'alert-danger')
        else:
            flash(error_message('item', item_name, 'browser'), 'alert-danger')
            return redirect(url_for('show_category',
                                    category_name=category.name))
    else:
        flash(error_message('category', category_name, 'browser'),
              'alert-danger')
        return redirect(url_for('show_catalog'))


@app.route('/catalog/<category_name>/<item_name>/delete',
           methods=['GET', 'POST'])
@login_required
def delete_item(category_name, item_name):
    '''Try to find a item in the database whose name and category name match
       the uri. If no category or item is found, flash an error message and
       redirect to the catalog or category page, respectively.
       If a match is found, display the page to delete this item for
       a GET request. In the case of a DELETE request, delete item from
       database, flash a success message, and redirect to the item category
       page.'''
    category = (db_session.query(Category)
                .filter_by(name=category_name).one_or_none())
    if category:
        item = (db_session.query(Item)
                .filter_by(name=item_name, category_id=category.id)
                .one_or_none())
        if item:
            if session['user_id'] != item.user_id:
                flash('You are not authorized to delete this item',
                      'alert-danger')
                return redirect(url_for('show_item',
                                        category_name=category.name,
                                        item_name=item.name))
            if request.method == 'GET':
                categories = db_session.query(Category).order_by('name').all()
                return render_template('delete_item.html', item=item,
                                       categories=categories)
            elif request.method == 'POST':
                category = item.category
                db_session.delete(item)
                db_session.commit()
                flash('item successfully deleted', 'alert-success')
                return redirect(url_for('show_category',
                                        category_name=category.name))
        else:
            flash(error_message('item', item_name, 'browser'), 'alert-danger')
            return redirect(url_for('show_category',
                                    category_name=category.name))
    else:
        flash(error_message('category', category_name, 'browser'),
              'alert-danger')
        return redirect(url_for('show_catalog'))


# API routing
@csrf.exempt
@app.route('/api/catalog', methods=['GET', 'POST'])
@verify_token
def api_catalog():
    if request.method == 'GET':
        categories = db_session.query(Category).order_by('name').all()
        return jsonify(catalog={'categories': [get_category_json(category)
                                               for category in categories]})

    elif request.method == 'POST':
        '''POST method to create a new item: try to add a new item to
           the database with the the request parameters. If item is
           successfully added to the database, return a json with success
           message. If not, rollback the changes and return a json with
           an error message.'''
        try:
            item = create_item(request.args.get('category_id'),
                               request.args.get('name'),
                               request.args.get('description'),
                               g.user.id)
            return jsonify(Item=item.serialize)
        except IntegrityError as e:
            db_session.rollback()
            return jsonify(Error=e.args[0]), 400


@app.route('/api/catalog/<category_name>', methods=['GET'])
def api_category(category_name):
    category = (db_session.query(Category)
                .filter_by(name=category_name)
                .one_or_none())
    if category:
        return jsonify(Category=get_category_json(category))
    else:
        return error_message('category', category_name, 'api')


@csrf.exempt
@app.route('/api/catalog/<category_name>/<item_name>',
           methods=['GET', 'PUT', 'DELETE'])
@verify_token
def api_item(category_name, item_name):
    category = (db_session.query(Category)
                .filter_by(name=category_name)
                .one_or_none())
    if category:
        item = (db_session.query(Item)
                .filter_by(name=item_name, category_id=category.id)
                .one_or_none())
        if item:
            if request.method == 'GET':
                # Return a json corresponding to the item.
                return jsonify(Item=item.serialize)
            elif request.method == 'PUT':
                if g.user.id != item.user_id:
                    return jsonify(
                        Error='You are not authorized to edit this item')
                '''PUT method to update an item: try to update the item
                   in the database with the values passed in the request.
                   If item is successfully updated, return a json
                   corresponding to the item. If not, rollback the changes
                   and return a json with an error message.'''
                try:
                    update_item(item, request.args['category_id'],
                                request.args['name'],
                                request.args['description'])
                    return jsonify(Item=item.serialize)
                except IntegrityError as e:
                    db_session.rollback()
                    return jsonify(Error=e.args[0]), 400
            elif request.method == 'DELETE':
                if g.user.id != item.user_id:
                    return jsonify(
                        Error='You are not authorized to delete this item')
                # delete item from database
                db_session.delete(item)
                db_session.commit()
                return jsonify(Success='item deleted')
        else:
            return error_message('item', item_name, 'api')
    else:
            return error_message('category', category_name, 'api')


@app.errorhandler(404)
def not_found(message):
    flash(message, 'alert-danger')
    return render_template('error.html'), 404


if __name__ == '__main__':
    # TODO: change secret key
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
