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

from flask_httpauth import HTTPBasicAuth
auth = HTTPBasicAuth()

# Connect to database
engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
db_session = DBSession()

app = Flask(__name__)



@app.route('/login')
def showLogin():
    # Create a state token to prevent request forgery.
    # Store it in session for later validation.
    state = hashlib.sha256(os.urandom(1024)).hexdigest()
    session['state'] = state
    # Set the token state in the HTML while serving it.
    return render_template('login.html', state=state)


def facebook_graph_api_request(url, method):
    h = httplib2.Http()
    result = h.request('https://graph.facebook.com' + url, method)[1]
    return json.loads(result.decode())


@app.route('/logout')
def disconnect():
    if session.get('provider') == 'google':
        # Revoke OAuth credentials
        credentials = client.OAuth2Credentials.from_json(session['credentials'])
        credentials.revoke(httplib2.Http())

        # Clear session.
        del session['provider']
        del session['user_id']
        del session['email']
        del session['credentials']

        return redirect(url_for('show_catalog'))

    if session.get('provider') == 'facebook':
        # Revoke access token
        url = ('/{0}/permissions?access_token={1}'.format(session['facebook_id'],
                                                          session['access_token']))
        revoke_response = facebook_graph_api_request(url, 'DELETE')
        if revoke_response.get('success'):
            # Clear session.
            del session['provider']
            del session['user_id']
            del session['email']
            del session['facebook_id']
            del session['access_token']

            return redirect(url_for('show_catalog'))

        else:
            return jsonify(revoke_response)

    if session.get('provider') == 'github':
        # Revoke access token not working
        '''
        with open('github_oauth_credentials.json') as secrets_file:
            secret_json = json.load(secrets_file)
        client_id = secret_json['client_id']
        client_secret = secret_json['client_secret']
        url = ('https://api.github.com/applications/{0}/tokens/{1}'
               .format(client_id, session['access_token']))
        h = httplib2.Http()
        h.add_credentials(client_id, client_secret)
        result = h.request(url, method='DELETE')[1]
        return result
        '''

        # Clear session.
        del session['provider']
        del session['user_id']
        del session['email']
        del session['access_token']

        return redirect(url_for('show_catalog'))

    if session.get('provider') == 'twitter':

        # Clear session.
        del session['provider']
        del session['user_id']
        del session['email']
        del session['resource_owner_key']
        del session['resource_owner_secret']

        return redirect(url_for('show_catalog'))

    if session.get('provider') == 'linkedin':

        # Clear session.
        del session['provider']
        del session['user_id']
        del session['email']
        del session['access_token']

        return redirect(url_for('show_catalog'))



@app.route('/oauth2callback/<provider>')
def oauth2callback(provider):
    # Ensure that the request is not a forgery and that the user sending
    # this connect request is the expected user.
    if request.args.get('state', '') != session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    redirect_uri=url_for('oauth2callback', provider=provider,
                                 _external=True)

    if provider == 'google':
        flow = client.flow_from_clientsecrets('google_oauth_credentials.json',
                                              scope='openid email profile',
                                              redirect_uri=redirect_uri)
        if 'code' not in request.args:
            auth_uri = flow.step1_get_authorize_url(state=request.args.get('state'))
            return redirect(auth_uri)
        else:
            auth_code = request.args.get('code')
            credentials = flow.step2_exchange(auth_code)
            email = credentials.id_token['email']

            # Check if user exists, if not create new user
            user = db_session.query(User).filter_by(email=email).first()
            if not user:
                user = User(email=email)
                db_session.add(user)
                db_session.commit()

            # Update session parameters
            session['provider'] = 'google'
            session['user_id'] = user.id
            session['email'] = email
            session['credentials'] = credentials.to_json()

            return redirect(url_for('show_catalog'))
    elif provider == 'facebook':
        with open('facebook_oauth_credentials.json') as secrets_file:
            secret_json = json.load(secrets_file)['web']
        app_secret = secret_json['app_secret']
        app_id = secret_json['app_id']
        if 'code' not in request.args:
            return redirect('https://www.facebook.com/v2.10/dialog/oauth?'
                            'client_id={0}&redirect_uri={1}&state={2}&scope=email'
                            .format(app_id,
                                    redirect_uri,
                                    request.args.get('state')))
        else:
            auth_code = request.args.get('code')

            # Exchange Code for an Access Token.
            url = ('/v2.10/oauth/access_token?'
                   'client_id={0}&'
                   'redirect_uri={1}&'
                   'client_secret={2}&'
                   'code={3}'.format(app_id, redirect_uri, app_secret,
                                     auth_code))
            access_token = facebook_graph_api_request(url, 'GET')['access_token']

            # Obtain App Token.
            url = ('/oauth/access_token?'
                   'client_id={0}&'
                   'client_secret={1}&'
                   'grant_type=client_credentials'.format(app_id, app_secret))
            app_token = facebook_graph_api_request(url, 'GET')['access_token']

            # Inspect Access Token using App Token.
            url = ('/debug_token?'
                   'input_token={0}&'
                   'access_token={1}'.format(access_token, app_token))
            response_json = facebook_graph_api_request(url, 'GET')['data']

            if response_json['is_valid'] and response_json['app_id'] == app_id:
                # Use token to get user info from Facebook.
                url = ('/v2.10/me?access_token={0}&fields=name,id,email'
                       .format(access_token))
                user_data = facebook_graph_api_request(url, 'GET')
                email = user_data['email']

                # Check if user exists, if not create new user
                user = db_session.query(User).filter_by(email=email).first()
                if not user:
                    user = User(email=email)
                    db_session.add(user)
                    db_session.commit()

                # Update session parameters
                session['provider'] = 'facebook'
                session['user_id'] = user.id
                session['email'] = email
                session['facebook_id'] = user_data["id"]
                session['access_token'] = access_token

                return redirect(url_for('show_catalog'))

            else:
                return 'access_token not valid'
    elif provider == 'github':
        with open('github_oauth_credentials.json') as secrets_file:
            secret_json = json.load(secrets_file)
        client_id = secret_json['client_id']
        client_secret = secret_json['client_secret']

        if 'code' not in request.args:
            return redirect('https://github.com/login/oauth/authorize?'
                            'client_id={0}&redirect_uri={1}&state={2}&scope=user:email'
                            .format(client_id,
                                    redirect_uri,
                                    request.args.get('state')))
        else:
            auth_code = request.args.get('code')

            # Exchange Code for an Access Token.
            url = ('https://github.com/login/oauth/access_token?'
                   'client_id={0}&'
                   'redirect_uri={1}&'
                   'client_secret={2}&'
                   'code={3}'.format(client_id, redirect_uri, client_secret,
                                     auth_code))
            h = httplib2.Http()
            result = h.request(url, method='POST', headers={
                'Accept': 'application/json'})[1]
            access_token = json.loads(result.decode())['access_token']

            # Use token to get user info from GitHub.
            url = 'https://api.github.com/user/emails'
            h = httplib2.Http()
            result = h.request(url, method='GET', headers={
                'Authorization': 'token {}'.format(access_token)})[1]
            for json_email in json.loads(result.decode()):
                if json_email['primary'] == True:
                    email = json_email['email']

            # Check if user exists, if not create new user
            user = db_session.query(User).filter_by(email=email).first()
            if not user:
                user = User(email=email)
                db_session.add(user)
                db_session.commit()

            # Update session parameters
            session['provider'] = 'github'
            session['user_id'] = user.id
            session['email'] = email
            session['access_token'] = access_token

            return redirect(url_for('show_catalog'))

    elif provider == 'twitter':
        # Get credentials
        with open('twitter_oauth_credentials.json') as secrets_file:
            secret_json = json.load(secrets_file)

        if 'oauth_token' not in request.args and 'oauth_verifier' not in request.args:
            # Obtain a request token.
            request_token_url = 'https://api.twitter.com/oauth/request_token'
            oauth = OAuth1(secret_json['consumer_key'],
                           client_secret=secret_json['consumer_secret'],
                           callback_uri=(redirect_uri + '?state=' +
                                         request.args.get('state')))
            r = requests.post(url=request_token_url, auth=oauth)
            credentials = parse_qs(r.content.decode())
            if credentials.get('oauth_callback_confirmed')[0] == 'true':
                session['resource_owner_key'] = credentials.get('oauth_token')[0]
                session['resource_owner_secret'] = credentials.get('oauth_token_secret')[0]

                # Redirect the user
                base_authorization_url = 'https://api.twitter.com/oauth/authenticate'
                authorize_url = base_authorization_url + '?oauth_token='
                authorize_url += session['resource_owner_key']
                return redirect(authorize_url)
            else:
                flash('error while requesting token to Twitter')
                return redirect(url_for('show_catalog'))
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
                credentials = parse_qs(r.content.decode())
                session['resource_owner_key'] = credentials.get('oauth_token')[0]
                session['resource_owner_secret'] = credentials.get('oauth_token_secret')[0]

                # Access user info.
                protected_url = ('https://api.twitter.com/1.1/account/'
                                 'verify_credentials.json?include_email=true')
                oauth = OAuth1(secret_json['consumer_key'],
                    client_secret=secret_json['consumer_secret'],
                    resource_owner_key=session['resource_owner_key'],
                    resource_owner_secret=session['resource_owner_secret']
                )
                r = requests.get(url=protected_url, auth=oauth)
                email = json.loads(r.content.decode())['email']

                # Check if user exists, if not create new user
                user = db_session.query(User).filter_by(email=email).first()
                if not user:
                    user = User(email=email)
                    db_session.add(user)
                    db_session.commit()

                # Update session parameters
                session['provider'] = 'twitter'
                session['user_id'] = user.id
                session['email'] = email

                return redirect(url_for('show_catalog'))
    elif provider == 'linkedin':
        # Get credentials
        with open('linkedin_oauth_credentials.json') as secrets_file:
            secret_json = json.load(secrets_file)

        if 'code' not in request.args:
            return redirect('https://www.linkedin.com/oauth/v2/authorization?'
                            'response_type=code&client_id={0}&redirect_uri={1}&'
                            'state={2}'.format(secret_json['client_id'],
                                               redirect_uri,
                                               request.args.get('state')))

        else:
            auth_code = request.args.get('code')

            # Exchange Code for an Access Token.
            url = ('https://www.linkedin.com/oauth/v2/accessToken?'
                   'grant_type=authorization_code&'
                   'client_id={0}&'
                   'redirect_uri={1}&'
                   'client_secret={2}&'
                   'code={3}'.format(secret_json['client_id'], redirect_uri,
                                     secret_json['client_secret'], auth_code))
            h = httplib2.Http()
            result = h.request(url, method='POST', headers={
                    'Content-Type': 'application/x-www-form-urlencoded'})[1]
            access_token = json.loads(result.decode())['access_token']

            # Use token to get user info from LinkedIn.
            url = 'https://api.linkedin.com/v1/people/~:(email-address)?format=json'
            h = httplib2.Http()
            result = h.request(url, method='GET', headers={
                'Authorization': 'Bearer {}'.format(access_token)})[1]
            email = json.loads(result.decode())['emailAddress']

            # Check if user exists, if not create new user
            user = db_session.query(User).filter_by(email=email).first()
            if not user:
                user = User(email=email)
                db_session.add(user)
                db_session.commit()

            # Update session parameters
            session['provider'] = 'linkedin'
            session['user_id'] = user.id
            session['email'] = email
            session['access_token'] = access_token

            return redirect(url_for('show_catalog'))








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
