#!/usr/bin/env python3
import twitter_sign
from urllib.parse import quote, parse_qs

from oauth2client import client
import httplib2
import json

import requests
from requests_oauthlib import OAuth1

from sqlalchemy import create_engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker
from models import Base, User, Item, Category

from flask import Flask, request, render_template, redirect, url_for, flash
from flask import jsonify, g, session, make_response

import hashlib, os

import sys

from functools import wraps

from flask_httpauth import HTTPBasicAuth
auth = HTTPBasicAuth()

# Connect to database
engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
db_session = DBSession()

app = Flask(__name__)


def debug():
    assert app.debug == False


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login first')
            return redirect(url_for('show_login'))
        return f(*args, **kwargs)
    return decorated_function


@app.route('/login')
def show_login():
    # Create a state token to prevent request forgery.
    # Store it in session for later validation.
    state = hashlib.sha256(os.urandom(1024)).hexdigest()
    session['state'] = state
    # Set the token state in the HTML while serving it.
    return render_template('login.html', state=state)


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
    if 'state' in session:
        del session['state']


@app.route('/logout')
def disconnect():
    if session.get('provider') == 'google':
        # Revoke OAuth credentials
        credentials = client.OAuth2Credentials.from_json(session['credentials'])
        try:
            credentials.revoke(httplib2.Http())
        except:
            flash('Revoking OAuth credentials failed')

    elif session.get('provider') == 'facebook':
        # Revoke access token
        url = 'https://graph.facebook.com/{}/permissions'.format(quote(session['facebook_id']))
        payload = {'access_token': session['access_token']}
        r = requests.delete(url, params=payload)
        if 'error' in r.json():
            flash('Revoking OAuth credentials failed')

    elif session.get('provider') == 'github':
        # Revoke access token not working
        with open('oauth_credentials.json') as secrets_file:
            secret_json = json.load(secrets_file)['github']
        client_id = secret_json['client_id']
        client_secret = secret_json['client_secret']
        url = ('https://api.github.com/applications/' + quote(client_id) +
            '/tokens/' + quote(session['access_token']))
        r = requests.delete(url, auth=(client_id, client_secret))
        if r.status_code != 204:
            flash('Revoking OAuth credentials failed')

    clear_session()
    flash('You have been logged out')
    return redirect(url_for('show_catalog'))


# TODO: handle case when user cancel oauth signin
@app.route('/oauth2callback/<provider>')
def oauth_callback(provider):
    #Check to see if user is already logged in and redirect logged in user.
    if session.get('user_id'):
        flash('You are already logged in')
        return redirect(url_for('show_catalog'))

    # Ensure that the request is not a forgery and that the user sending
    # this connect request is the expected user.
    if request.args.get('state') != session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    redirect_uri = url_for('oauth_callback', provider=provider, _external=True)

    # Get credentials
    with open('oauth_credentials.json') as secrets_file:
        secret_json = json.load(secrets_file)[provider]

    auth_code = request.args.get('code')

    # Google OAuth
    if provider == 'google':
        flow = client.flow_from_clientsecrets('google_oauth_credentials.json',
                                              scope='openid email profile',
                                              redirect_uri=redirect_uri)
        if auth_code:
            credentials = flow.step2_exchange(auth_code)
            user = login_or_register_user(provider, credentials.id_token['email'])
            session['credentials'] = credentials.to_json()
            return redirect(url_for('show_catalog'))
        else:
            auth_uri = flow.step1_get_authorize_url(
                state=request.args.get('state')
            )
            return redirect(auth_uri)

    # Facebook OAuth
    elif provider == 'facebook':
        app_secret = secret_json['app_secret']
        app_id = secret_json['app_id']
        if auth_code:
            # Exchange code for an access token.
            url = 'https://graph.facebook.com/v2.10/oauth/access_token'
            payload = {'client_id': app_id, 'redirect_uri': redirect_uri,
                       'client_secret': app_secret, 'code': auth_code}
            r = requests.get(url, params=payload)
            access_token = r.json()['access_token']

            # Obtain app token.
            payload = {'client_id': app_id, 'client_secret': app_secret,
                       'grant_type': 'client_credentials'}
            r = requests.get(url, params=payload)
            app_token = r.json()['access_token']

            # Inspect access token using app token.
            url = 'https://graph.facebook.com/debug_token'
            payload = {'input_token': access_token, 'access_token': app_token}
            r = requests.get(url, params=payload)

            if 'error' in r.json():
                flash('access token and/or app token not valid')
                return redirect(url_for('show_login'))

            # Check app id
            elif r.json()['data']['is_valid'] and r.json()['data']['app_id'] == app_id:
                # Use token to get user info from Facebook.
                url = 'https://graph.facebook.com/v2.10/me'
                payload = {'access_token': access_token,
                           'fields': 'name,id,email'}
                r = requests.get(url, params=payload)
                user = login_or_register_user(provider, r.json()['email'])

                # Update session parameters
                session['facebook_id'] = r.json()["id"]
                session['access_token'] = access_token

                return redirect(url_for('show_catalog'))

            else:
                flash('access_token not valid for this app')
                return redirect(url_for('show_login'))
        else:
            url = 'https://www.facebook.com/v2.10/dialog/oauth'
            payload = {'client_id': app_id, 'redirect_uri': redirect_uri,
                       'state': request.args.get('state'), 'scope': 'email'}
            redirect_req = requests.PreparedRequest()
            redirect_req.prepare_url(url, payload)
            return redirect(redirect_req.url)


    # GitHub OAuth
    elif provider == 'github':
        client_id = secret_json['client_id']
        client_secret = secret_json['client_secret']
        if auth_code:
            # Exchange Code for an Access Token.
            url = 'https://github.com/login/oauth/access_token'
            payload = {'client_id': client_id, 'redirect_uri': redirect_uri,
                       'client_secret': client_secret, 'code': auth_code}
            headers = {'Accept': 'application/json'}
            r = requests.post(url, params=payload, headers=headers)
            access_token = r.json()['access_token']

            # Use token to get user info from GitHub.
            url = 'https://api.github.com/user/emails'
            headers = {'Authorization': 'token {}'.format(access_token)}
            r = requests.get(url, headers=headers)
            for email in r.json():
                if email['primary'] == True:
                    user = login_or_register_user(provider, email['email'])

                    # Update session parameters
                    session['access_token'] = access_token

                    return redirect(url_for('show_catalog'))
            # If no email is obtained from GitHub, flash error message and
            # redirect to login page
            flash('error: could not obtain credentials from Github')
            return redirect(url_for('show_login'))
        else:
            url = 'https://github.com/login/oauth/authorize'
            payload = {'client_id': client_id, 'redirect_uri': redirect_uri,
                       'state': request.args.get('state'),
                       'scope': 'user:email'}
            redirect_req = requests.PreparedRequest()
            redirect_req.prepare_url(url, payload)
            return redirect(redirect_req.url)

    # LinkedIn OAuth
    elif provider == 'linkedin':
        if auth_code:
            # Exchange Code for an Access Token.
            url = 'https://www.linkedin.com/oauth/v2/accessToken'
            payload = {'grant_type': 'authorization_code',
                       'client_id': secret_json['client_id'],
                       'redirect_uri': redirect_uri,
                       'client_secret': secret_json['client_secret'],
                       'code': auth_code}
            headers = {'Content-Type': 'application/x-www-form-urlencoded'}
            r = requests.post(url, params=payload, headers=headers)
            access_token = r.json()['access_token']

            # Use token to get user info from LinkedIn.
            url = 'https://api.linkedin.com/v1/people/~:(email-address)'
            payload = {'format': 'json'}
            headers = {'Authorization': 'Bearer {}'.format(access_token)}
            r = requests.get(url, params=payload, headers=headers)
            email = r.json()['emailAddress']
            user = login_or_register_user(provider, email)

            # Update session parameters
            session['access_token'] = access_token

            return redirect(url_for('show_catalog'))
        else:
            url = 'https://www.linkedin.com/oauth/v2/authorization'
            payload = {'response_type': 'code',
                       'client_id': secret_json['client_id'],
                       'redirect_uri': redirect_uri,
                       'state': request.args.get('state')}
            redirect_req = requests.PreparedRequest()
            redirect_req.prepare_url(url, payload)
            return redirect(redirect_req.url)

    # Twitter OAuth
    elif provider == 'twitter':
        if 'oauth_token' not in request.args or 'oauth_verifier' not in request.args:
            # Obtain a request token.
            payload = {'state': request.args.get('state')}
            callback_req = requests.PreparedRequest()
            callback_req.prepare_url(redirect_uri, payload)
            request_token_url = 'https://api.twitter.com/oauth/request_token'
            oauth = OAuth1(secret_json['consumer_key'],
                           client_secret=secret_json['consumer_secret'],
                           callback_uri=callback_req.url)
            r = requests.post(url=request_token_url, auth=oauth)
            credentials = parse_qs(r.text)
            if credentials.get('oauth_callback_confirmed')[0] == 'true':
                session['resource_owner_key'] = credentials.get('oauth_token')[0]
                session['resource_owner_secret'] = credentials.get('oauth_token_secret')[0]

                # Redirect the user
                url = 'https://api.twitter.com/oauth/authenticate'
                payload = {'oauth_token': session['resource_owner_key']}
                redirect_req = requests.PreparedRequest()
                redirect_req.prepare_url(url, payload)
                return redirect(redirect_req.url)
            else:
                flash('error while requesting token to Twitter')
                return redirect(url_for('show_login'))
        else:
            # Verify that the token matches the request token received
            # in the first step of the flow.
            if request.args.get('oauth_token') == session['resource_owner_key']:

                # Convert the request token to an access token.
                access_token_url = 'https://api.twitter.com/oauth/access_token'
                oauth = OAuth1(secret_json['consumer_key'],
                    client_secret=secret_json['consumer_secret'],
                    resource_owner_key=session['resource_owner_key'],
                    resource_owner_secret=session['resource_owner_secret'],
                    verifier=request.args.get('oauth_verifier')
                )
                r = requests.post(url=access_token_url, auth=oauth)
                credentials = parse_qs(r.text)
                session['resource_owner_key'] = credentials.get('oauth_token')[0]
                session['resource_owner_secret'] = credentials.get('oauth_token_secret')[0]

                # Access user info.
                protected_url = ('https://api.twitter.com/1.1/account/'
                                 'verify_credentials.json')
                payload = {'include_email': 'true'}
                oauth = OAuth1(secret_json['consumer_key'],
                    client_secret=secret_json['consumer_secret'],
                    resource_owner_key=session['resource_owner_key'],
                    resource_owner_secret=session['resource_owner_secret']
                )
                r = requests.get(url=protected_url, params=payload, auth=oauth)
                email = r.json()['email']
                user = login_or_register_user(provider, email)

                return redirect(url_for('show_catalog'))




def login_or_register_user(provider, email):
    '''Check if user exists, if not create new user'''
    user = db_session.query(User).filter_by(email=email).first()
    if not user:
        user = User(email=email)
        db_session.add(user)
        db_session.commit()
    session['provider'] = provider
    session['user_id'] = user.id
    session['email'] = user.email
    return user


@auth.verify_password
def verify_password(email_or_token, password):
    user_id = User.verify_auth_token(email_or_token)
    if user_id:
        user = db_session.query(User).get(user_id)
    else:
        user = db_session.query(User).filter_by(email=email_or_token).first()
        if not user or not user.verify_password(password):
            return False
    g.user = user
    return True


# Get a token for a user with login credentials
@app.route('/token', methods = ['GET'])
@auth.login_required
def get_auth_token():
    token = g.user.generate_auth_token()
    return jsonify({'token': token.decode('ascii')})


# Helper methods
def error_message(model, model_name, request_type):
    error_message = "no {0} '{1}' found".format(model, model_name)
    if request_type == 'api':
        return (jsonify(Error=error_message), 404)
    elif request_type == 'browser':
        return 'error: ' + error_message


def create_item(category_id, name, description):
    item = Item(name=name, description=description, category_id=category_id)
    db_session.add(item)
    db_session.commit()
    return item


def update_item(item, params):
    item.name = params['name']
    item.description = params['description']
    item.category_id = params['category_id']
    db_session.add(item)
    db_session.commit()


def get_category_json(category):
    # API helper function that returns a json with all items from a category
    items = db_session.query(Item).filter_by(category_id=category.id).all()
    category_json = category.serialize
    category_json['items'] = [item.serialize for item in items]
    return category_json


@app.route('/')
@app.route('/catalog', methods=['GET'])
def show_catalog():
    '''Display the catalog page'''
    categories = db_session.query(Category).all()
    latest_items = (db_session.query(Item)
                    .order_by(Item.id.desc()).limit(10).all())
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
        items = db_session.query(Item).filter_by(category_id=category.id).all()
        categories = db_session.query(Category).all()
        return render_template('show_category.html',
                               categories=categories,
                               category=category,
                               items=items)
    else:
        flash(error_message('category', category_name, 'browser'))
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
            categories = db_session.query(Category).all()
            return render_template('show_item.html',
                                   categories=categories,
                                   item=item)
        else:
            flash(error_message('item', item_name, 'browser'))
            return redirect(url_for('show_category',
                                    category_name=category.name))
    else:
        flash(error_message('category', category_name, 'browser'))
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
                            request.form['description'])
                flash('item successfully created')
                return redirect(url_for('show_category',
                                        category_name=category.name))
            except IntegrityError as e:
                db_session.rollback()
                flash('item not created due to error: ' + e.args[0])
        else:
            flash(error_message('category with id ',
                                request.form['category_id'],
                                'browser'))
    categories = db_session.query(Category).all()
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
            if request.method == 'GET':
                categories = db_session.query(Category).all()
                return render_template('edit_item.html',
                                       item=item,
                                       categories=categories)
            elif request.method == 'POST':
                try:
                    update_item(item,
                                {'name': request.form['name'],
                                 'description': request.form['description'],
                                 'category_id': request.form['category_id']})
                    flash('item successfully edited')
                    return redirect(url_for('show_category',
                                            category_name=item.category.name))
                except IntegrityError as e:
                    db_session.rollback()
                    flash('item not edited due to error: ' + e.args[0])
        else:
            flash(error_message('item', item_name, 'browser'))
            return redirect(url_for('show_category',
                                    category_name=category.name))
    else:
        flash(error_message('category', category_name, 'browser'))
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
            if request.method == 'GET':
                categories = db_session.query(Category).all()
                return render_template('delete_item.html',
                                       categories=categories,
                                       item=item)
            elif request.method == 'POST':
                category = item.category
                db_session.delete(item)
                db_session.commit()
                flash('item successfully deleted')
                return redirect(url_for('show_category',
                                        category_name=category.name))
        else:
            flash(error_message('item', item_name, 'browser'))
            return redirect(url_for('show_category',
                                    category_name=category.name))
    else:
        flash(error_message('category', category_name, 'browser'))
        return redirect(url_for('show_catalog'))


# API routing
@app.route('/api/catalog', methods=['GET', 'POST'])
def api_catalog():
    if request.method == 'GET':
        categories = db_session.query(Category).all()
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
                               request.args.get('description'))
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


@app.route('/api/catalog/<category_name>/<item_name>',
           methods=['GET', 'PUT', 'DELETE'])
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
                '''PUT method to update an item: try to update the item
                   in the database with the values passed in the request.
                   If item is successfully updated, return a json
                   corresponding to the item. If not, rollback the changes
                   and return a json with an error message.'''
                try:
                    update_item(item,
                                {'name': request.args['name'],
                                 'description': request.args['description'],
                                 'category_id': request.args['category_id']})
                    return jsonify(Item=item.serialize)
                except IntegrityError as e:
                    db_session.rollback()
                    return jsonify(Error=e.args[0]), 400
            elif request.method == 'DELETE':
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
    flash(message)
    return render_template('error.html'), 404


if __name__ == '__main__':
    # TODO: change secret key
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
