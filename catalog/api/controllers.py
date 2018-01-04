#!/usr/bin/env python3
'''Catalog app API controllers.'''
import time
from functools import wraps

from redis import Redis
from flask import Blueprint, request, g, jsonify, session, render_template

from catalog import app, db_session, csrf
from catalog.models import User, Item, Category
from catalog.helpers import error_message, create_item, update_item, login_required

# Define the blueprint: 'api', set its url prefix: app.url/catalog/api/v1.0
api = Blueprint('api', __name__, url_prefix='/catalog/api/v1.0',
                template_folder='templates')

redis = Redis()
# Response callback to get the sum of the key values in a hash
redis.set_response_callback('HGETALL',
                            lambda x: sum([int(i) for i in x[1::2]]))


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


def rate_limited(f):
    '''Limit number of requests made to API.'''
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Get options from config
        limit = app.config['MAX_REQUESTS']
        time_span = app.config['TIME_SPAN']
        bucket_interval = app.config['BUCKET_INTERVAL']

        # Set Redis hash name
        name = 'API:{}'.format(request.remote_addr)

        # Divide time in buckets
        bucket_number = (int(time.time()) % time_span) // bucket_interval
        total_buckets = time_span // bucket_interval

        # Set Redis key name
        key = 'Bucket{}'.format(bucket_number)

        # Redis transactions to increment corresponding bucket, clear old
        # requests, renew the bucket expiration, and get number of recent
        # requests to API.  Inspired by:
        # https://gist.github.com/chriso/54dd46b03155fcf555adccea822193da
        pipe = redis.pipeline()
        pipe.hincrby(name, key)
        pipe.hdel(name, 'Bucket{}'.format((bucket_number + 1) % total_buckets))
        pipe.expire(name, time_span)
        pipe.hgetall(name)
        recent_requests = pipe.execute()[3]

        if recent_requests > limit:
            return jsonify(Error='You hit the rate limit'), 429
        return f(*args, **kwargs)
    return decorated_function


def get_category_json(category):
    '''Return a json with all items from a category.'''
    items = db_session.query(Item).filter_by(category_id=category.id).all()
    category_json = category.serialize
    category_json['items'] = [item.serialize for item in items]
    return category_json


@api.route('/token', methods=['GET'])
@login_required
def get_api_auth_token():
    '''Get a token for a user with login credentials.'''
    user = db_session.query(User).get(session['user_id'])
    token = user.generate_auth_token()
    return render_template('api/api_token.html', token=token.decode('ascii'),)


@api.route('/<category_name>', methods=['GET'])
@rate_limited
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
@api.route('/items', methods=['GET', 'POST'])
@rate_limited
@verify_token
def api_catalog():
    '''Return all items or create a new item.

    GET: Return the entire catalog in json.
    POST: Create a new item.
    '''
    if request.method == 'GET':
        categories = db_session.query(Category).order_by('name').all()
        return jsonify(catalog={'categories': [get_category_json(category)
                                               for category in categories]})

    elif request.method == 'POST':
        try:
            item = create_item(g.user.id)
            if item:
                return jsonify(Item=item.serialize)
            else:
                return jsonify(Error='Item not created'), 422

        # Rollback the changes and display error message if new item name is
        # blank or already taken.
        except IntegrityError as e:
            db_session.rollback()
            return jsonify(Error=e.args[0]), 422


@csrf.exempt
@api.route('/<category_name>/<item_name>',
           methods=['GET', 'PUT', 'DELETE'])
@rate_limited
@verify_token
def api_item(category_name, item_name):
    '''Return an item or update or delete it.

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

                try:
                    update_item(item)
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
