#!/usr/bin/env python3
'''Catalog app OAuth controllers.'''
import json
from os import urandom
from hashlib import sha256
from functools import wraps

from flask import Blueprint, url_for, request, redirect, session, flash

from requests import PreparedRequest
from requests_oauthlib import OAuth1Session, OAuth2Session

from catalog import app, db_session
from catalog.models import User

# Define the blueprint: 'oauth'
oauth = Blueprint('oauth', __name__, template_folder='templates')


def redirect_user_if_already_logged_in(f):
    '''Redirect users that are already logged in.'''
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' in session:
            flash('You are already logged in', 'alert-primary')
            return redirect(url_for('show_catalog'))
        return f(*args, **kwargs)
    return decorated_function


def get_oauth_credentials(provider):
    '''Get OAuth credentials.'''
    secret_json = app.config['OAUTH_CREDENTIALS'][provider]

    if provider == 'twitter':
        client_id = secret_json['consumer_key']
        client_secret = secret_json['consumer_secret']
        redirect_uri = url_for('.oauth1_callback', provider=provider,
                               _external=True)
    else:
        client_id = secret_json['client_id']
        client_secret = secret_json['client_secret']
        redirect_uri = url_for('.oauth2_callback', provider=provider,
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


@oauth.route('/oauth2login/<provider>')
@redirect_user_if_already_logged_in
def oauth2_login(provider):
    '''Send user to the OAuth2 provider authorization page.'''

    # Get credentials and configure variables for OAuth2
    client_id, client_secret, redirect_uri = get_oauth_credentials(provider)
    if provider == 'google':
        scope = 'https://www.googleapis.com/auth/userinfo.email'
        base_url = 'https://accounts.google.com/o/oauth2/v2/auth'
    elif provider == 'github':
        scope = 'user:email'
        base_url = 'https://github.com/login/oauth/authorize'
    elif provider == 'facebook':
        scope = 'email'
        base_url = 'https://www.facebook.com/v2.10/dialog/oauth'
    elif provider == 'linkedin':
        scope = None
        base_url = 'https://www.linkedin.com/oauth/v2/authorization'

    # Redirect and flash error message if wrong provider is used
    else:
        flash('You can not login with this provider: {}'.format(provider),
              'alert-danger')
        return redirect(url_for('show_login'))

    auth_url, state = OAuth2Session(client_id, redirect_uri=redirect_uri,
                                    scope=scope).authorization_url(base_url)
    session['oauth_state'] = state
    return redirect(auth_url)


@oauth.route('/oauth2callback/<provider>')
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

    oauth_session = OAuth2Session(client_id, state=session['oauth_state'],
                                  redirect_uri=redirect_uri)
    try:
        # Fetch the access token
        oauth_session.fetch_token(token_url, client_secret=client_secret,
                                  authorization_response=request.url)

        # Fetch protected user info
        r = oauth_session.get(protected_url, params=payload)

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


@oauth.route('/oauth1login/<provider>')
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
            base_url = 'https://api.twitter.com/oauth/authorize'
            auth_url = twitter.authorization_url(base_url)
            return redirect(auth_url)
        else:
            flash('Error while requesting token to Twitter', 'alert-danger')
            return redirect(url_for('show_login'))

    # Redirect and flash error message if wrong provider is used
    else:
        flash('You can not login with this provider: {}'.format(provider),
              'alert-danger')
        return redirect(url_for('show_login'))


@oauth.route('/oauth1callback/<provider>')
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
