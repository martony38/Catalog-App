#!/usr/bin/env python3
'''Run the Catalog app server.'''
import json
import random
from hashlib import sha256
from os import urandom, path
from functools import wraps

from sqlalchemy import create_engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker
from flask import (Flask, request, render_template, redirect, url_for, flash,
                   jsonify, g, session)
from werkzeug.utils import secure_filename
from flask_seasurf import SeaSurf
from requests import PreparedRequest
from requests_oauthlib import OAuth1Session, OAuth2Session

from models import Base, User, Item, Category

# Connect to database
engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
db_session = DBSession()

app = Flask(__name__)

# Load configuration files
app.config.from_object('default_settings')
app.config.from_envvar('APPLICATION_SETTINGS')

# Add CSRF protection using SeaSurf (http://flask-seasurf.readthedocs.io)
csrf = SeaSurf(app)


def debug():
    '''Launch the debugger if debug mode is enabled.'''
    assert app.debug is False


def verify_token(f):
    '''Check API authorization token.'''
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method in ['POST', 'PUT', 'DELETE']:
            auth_header = request.headers.get('Authorization')

            # Check that request contains authorization header
            if not auth_header:
                return jsonify(Error='Missing authorization credentials'), 401

            auth_header = auth_header.split()

            # Check that authorization header is of the correct type
            if auth_header[0] != 'Bearer':
                return jsonify(Error='Wrong authorization type'), 401

            # Check authorization token
            user_id = User.verify_auth_token(auth_header[1])
            if not user_id:
                return jsonify(Error='Wrong authorization token'), 401

            # Fetch user from database and assign it to the request context
            user = db_session.query(User).get(user_id)
            if user:
                g.user = user
                return f(*args, **kwargs)
            return jsonify(Error='User id not found'), 404
        else:
            return f(*args, **kwargs)
    return decorated_function


def login_required(f):
    '''Redirect users that are not logged in.'''
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login first', 'alert-primary')
            return redirect(url_for('show_login'))
        return f(*args, **kwargs)
    return decorated_function


def redirect_user_if_already_logged_in(f):
    '''Redirect users that are already logged in.'''
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
    '''Get OAuth credentials.'''
    secret_json = app.config['OAUTH_CREDENTIALS'][provider]

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
    '''Check if user exists (if not create a new user) and log them in.'''
    user = db_session.query(User).filter_by(email=email).first()
    if not user:
        user = User(email=email)
        db_session.add(user)
        db_session.commit()
    session['provider'] = provider
    session['user_id'] = user.id
    session['email'] = user.email


def error_message(ressource, ressource_name, request_type):
    '''Return a ressource not found message for html and api endpoints.'''
    error_message = "no {0} '{1}' found".format(ressource, ressource_name)
    if request_type == 'api':
        return (jsonify(Error=error_message), 404)
    elif request_type == 'browser':
        return 'Error: ' + error_message


def allowed_file(filename):
    '''Check filename format.'''
    return ('.' in filename and
            filename.rsplit('.', 1)[1].lower() in
            app.config['ALLOWED_EXTENSIONS'])


def upload_file(file):
    '''Save file and return its url if successfull, None otherwise.'''
    if file:
        if file.filename != '':
            if allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(path.join('./static/' + app.config['UPLOAD_FOLDER'],
                                    filename))
                return url_for('static',
                               filename=(app.config['UPLOAD_FOLDER']+filename))
    return None


def create_item(category_id, name, description, user_id, image):
    '''Save a new item to database.'''
    image_url = upload_file(image)

    # If no image is uploaded, add a default image
    if not image_url:
        image_url = url_for('static', filename=(app.config['UPLOAD_FOLDER'] +
                            app.config['DEFAULT_IMAGE']))

    item = Item(name=name, description=description, category_id=category_id,
                user_id=user_id, image_url=image_url)
    db_session.add(item)
    db_session.commit()
    return item


def update_item(item, category_id, name, description, image):
    '''Update an existing item in the database.'''
    image_url = upload_file(image)

    # Skip update and call to database if there is nothing to update
    if ((not name or name == '') and
            (not description or description == '') and
            (not category_id or category_id == '') and
            not image_url):
        return

    if category_id and category_id != '':
        item.category_id = category_id
    if name and name != '':
        item.name = name
    if description and description != '':
        item.description = description
    if image_url:
        item.image_url = image_url
    db_session.add(item)
    db_session.commit()


def get_category_json(category):
    '''Return a json with all items from a category.'''
    items = db_session.query(Item).filter_by(category_id=category.id).all()
    category_json = category.serialize
    category_json['items'] = [item.serialize for item in items]
    return category_json



@app.route('/token', methods=['GET'])
@login_required
def get_api_auth_token():
    '''Get a token for a user with login credentials.'''
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
    '''Send user to the OAuth2 provider authorization page.'''

    # Get credentials and configure variables for OAuth2
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

    # Redirect and flash error message if wrong provider is used
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
    '''Handle callback from an OAuth2 provider and login user.'''

    # Get credentials and configure variables for OAuth2
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

    # Redirect and flash error message if wrong provider is used
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

        # Fetch protected user info
        r = oauth.get(protected_url, params=payload)

        # Extract the user email
        if provider == 'linkedin':
            email = r.json()['emailAddress']
        elif provider == 'github':
            for email_item in r.json():
                if email_item['primary'] is True:
                    email = email_item['email']
        else:
            email = r.json()['email']
    except:
        flash('Error: could not obtain your info from {}'.format(provider),
              'alert-danger')
        return redirect(url_for('show_login'))

    login_or_register_user(provider, email)
    return redirect(url_for('show_catalog'))


@app.route('/oauth1login/<provider>')
@redirect_user_if_already_logged_in
def oauth1_login(provider):
    '''Send user to the OAuth1 provider authorization page.'''

    # Get credentials for OAuth1
    client_key, client_secret, redirect_uri = get_oauth_credentials(provider)

    # Create a state token to prevent request forgery similarly to OAuth2.
    state = sha256(urandom(1024)).hexdigest()
    session['oauth_state'] = state
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

    # Redirect and flash error message if wrong provider is used
    else:
        flash('You can not login with this provider: {}'.format(provider),
              'alert-danger')
        return redirect(url_for('show_login'))


@app.route('/oauth1callback/<provider>')
@redirect_user_if_already_logged_in
def oauth1_callback(provider):
    '''Handle callback from an OAuth1 provider and login user.'''

    # Ensure that the request is not a forgery and that the user sending
    # this connect request is the expected user.
    if request.args.get('state') != session['oauth_state']:
        flash('Error: invalid state parameter', 'alert-danger')
        return redirect(url_for('show_login'))

    # Get credentials for OAuth1
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

            # Fetch protected user info
            protected_url = ('https://api.twitter.com/1.1/account/'
                             'verify_credentials.json')
            payload = {'include_email': 'true'}
            twitter = OAuth1Session(client_key, client_secret=client_secret,
                                    resource_owner_key=resource_owner_key,
                                    resource_owner_secret=resource_owner_sec)
            try:
                r = twitter.get(protected_url, params=payload)
                email = r.json()['email']
            except:
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
    '''Return the Catalog app homepage.'''
    categories = db_session.query(Category).order_by('name').all()
    latest_items = (db_session.query(Item)
                    .order_by(Item.id.desc()).limit(12).all())
    return render_template('catalog.html',
                           categories=categories,
                           latest_items=latest_items)


@app.route('/catalog/<category_name>', methods=['GET'])
def show_category(category_name):
    '''Return the page with all the items from a category.'''
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
    '''Return the page for an item.'''
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
    '''Create a new item.

    GET: Return the page with a form for creating a new item.
    POST: Try to create a new item.  If successfull, flash success
    message and redirect to newly created item's category page.
    '''
    if request.method == 'POST':
        category = (db_session.query(Category)
                    .get(request.form.get('category_id')))
        if category:
            try:
                create_item(category.id, request.form.get('name'),
                            request.form.get('description'),
                            session['user_id'], request.files.get('image'))
                flash('item successfully created', 'alert-success')
                return redirect(url_for('show_category',
                                        category_name=category.name))

            # Rollback the changes and display error message if new item name
            # is blank or already taken.
            except IntegrityError as e:
                db_session.rollback()
                flash('Item not created due to error: ' + e.args[0],
                      'alert-danger')
        else:
            flash(error_message('category with id ',
                                request.form.get('category_id'),
                                'browser'), 'alert-danger')

    categories = db_session.query(Category).order_by('name').all()
    return render_template('create_new_item.html', categories=categories,
                           max_file_size=app.config['MAX_CONTENT_LENGTH'])


@app.route('/catalog/<category_name>/<item_name>/edit',
           methods=['GET', 'POST'])
@login_required
def edit_item(category_name, item_name):
    '''Edit an existing item.

    GET: Return the page with a form for editing an existing item.
    POST: Try to update item.  If successfull, flash success
    message and redirect to updated item's category page.
    '''
    category = (db_session.query(Category)
                .filter_by(name=category_name).one_or_none())
    if category:
        item = (db_session.query(Item)
                .filter_by(name=item_name, category_id=category.id)
                .one_or_none())
        if item:

            # Only user whom item belongs to can edit it
            if session['user_id'] != item.user_id:
                flash('You are not authorized to edit this item',
                      'alert-danger')
                return redirect(url_for('show_item',
                                        category_name=category.name,
                                        item_name=item.name))

            if request.method == 'GET':
                categories = db_session.query(Category).order_by('name').all()
                return render_template('edit_item.html', item=item,
                    categories=categories,
                    max_file_size=app.config['MAX_CONTENT_LENGTH'])

            elif request.method == 'POST':
                try:
                    update_item(item, request.form.get('category_id'),
                                request.form.get('name'),
                                request.form.get('description'),
                                request.files.get('image'))
                    flash('item successfully edited', 'alert-success')
                    return redirect(url_for('show_category',
                                            category_name=item.category.name))

                # Rollback the changes and display error message if updated
                # item name is blank or already taken.
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
    '''Delete an item.

    GET: Return the page with a form for deleting an existing item.
    POST: Try to delete item.  If successfull, flash success
    message and redirect to updated item's category page.
    '''
    category = (db_session.query(Category)
                .filter_by(name=category_name).one_or_none())
    if category:
        item = (db_session.query(Item)
                .filter_by(name=item_name, category_id=category.id)
                .one_or_none())
        if item:

            # Only user whom items belongs to can delete it
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
@app.route('/api/v1/catalog', methods=['GET', 'POST'])
@verify_token
def api_catalog():
    '''Return the catalog or create a new item.

    GET: Return the entire catalog in json.
    POST: Create a new item.
    '''
    if request.method == 'GET':
        categories = db_session.query(Category).order_by('name').all()
        return jsonify(catalog={'categories': [get_category_json(category)
                                               for category in categories]})

    elif request.method == 'POST':
        category_id = (request.args.get('category_id') or
                       request.form.get('category_id'))
        name = request.args.get('name') or request.form.get('name')
        description = (request.args.get('description') or
                       request.form.get('description'))
        image = request.files.get('image')
        try:
            item = create_item(category_id, name, description, g.user.id,
                               image)
            return jsonify(Item=item.serialize)

        # Rollback the changes and display error message if new item name is
        # blank or already taken.
        except IntegrityError as e:
            db_session.rollback()
            return jsonify(Error=e.args[0]), 422


@app.route('/api/v1/catalog/<category_name>', methods=['GET'])
def api_category(category_name):
    '''Return all items from a category in json.'''
    category = (db_session.query(Category)
                .filter_by(name=category_name)
                .one_or_none())
    if category:
        return jsonify(Category=get_category_json(category))
    else:
        return error_message('category', category_name, 'api')


@csrf.exempt
@app.route('/api/v1/catalog/<category_name>/<item_name>',
           methods=['GET', 'PUT', 'DELETE'])
@verify_token
def api_item(category_name, item_name):
    '''Return info on an item or update or delete it.

    GET: Return item info in json.
    PUT: Edit item.
    DELETE: Delete item.
    '''
    category = (db_session.query(Category)
                .filter_by(name=category_name)
                .one_or_none())
    if category:
        item = (db_session.query(Item)
                .filter_by(name=item_name, category_id=category.id)
                .one_or_none())
        if item:

            if request.method == 'GET':
                return jsonify(Item=item.serialize)

            elif request.method == 'PUT':

                # Only user whom items belongs to can edit it
                if g.user.id != item.user_id:
                    return jsonify(Error='You are not authorized to edit '
                                   'this item'), 401

                category_id = (request.args.get('category_id') or
                               request.form.get('category_id'))
                name = request.args.get('name') or request.form.get('name')
                description = (request.args.get('description') or
                               request.form.get('description'))
                image = request.files.get('image')
                try:
                    update_item(item, category_id, name, description, image)
                    return jsonify(Item=item.serialize)

                # Rollback the changes and display error message if updated
                # item name is blank or already taken.
                except IntegrityError as e:
                    db_session.rollback()
                    return jsonify(Error=e.args[0]), 422

            elif request.method == 'DELETE':

                # Only user whom items belongs to can delete it
                if g.user.id != item.user_id:
                    return jsonify(Error='You are not authorized to delete '
                                   'this item'), 401

                db_session.delete(item)
                db_session.commit()
                return jsonify(Success='item deleted')

        else:
            return error_message('item', item_name, 'api')
    else:
            return error_message('category', category_name, 'api')


@app.errorhandler(404)
@app.errorhandler(413)
def handle_http_error(error):
    '''Return page not found or request too large error pages.'''
    return render_template('error.html', message=error), error.code


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
