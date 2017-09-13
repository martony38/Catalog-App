#!/usr/bin/env python3

from sqlalchemy import create_engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker
from models import Base, User, Item, Category

from flask import Flask, request, render_template, redirect, url_for, flash
from flask import jsonify

import sys

# Connect to database
engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
db_session = DBSession()

app = Flask(__name__)


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
