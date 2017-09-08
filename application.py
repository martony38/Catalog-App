#!/usr/bin/env python3

from sqlalchemy import create_engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm.exc import NoResultFound
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
    try:
        category = (db_session.query(Category)
                    .filter_by(name=category_name).one())
        items = db_session.query(Item).filter_by(category_id=category.id).all()
        categories = db_session.query(Category).all()
        return render_template('show_category.html',
                               categories=categories,
                               category=category,
                               items=items)
    except NoResultFound:
        flash('error: no category {} found'.format(category_name))
        return redirect(url_for('show_catalog'))


@app.route('/catalog/<category_name>/<item_name>', methods=['GET'])
def show_item(category_name, item_name):
    '''Try to find a item in the database whose name and category name match
       the uri. If a match is found, display the corresponding item page.
       If no category or item is found, flash an error message and redirect
       to the catalog or category page, respectively.'''
    try:
        category = (db_session.query(Category)
                    .filter_by(name=category_name).one())
        try:
            item = (db_session.query(Item)
                    .filter_by(name=item_name, category_id=category.id).one())
            categories = db_session.query(Category).all()
            return render_template('show_item.html',
                                   categories=categories,
                                   item=item)
        except NoResultFound:
            flash('error: no item {} found'.format(item_name))
            return redirect(url_for('show_category',
                                    category_name=category.name))
    except NoResultFound:
        flash('error: no category {} found'.format(category_name))
        return redirect(url_for('show_catalog'))


@app.route('/catalog/new', methods=['GET', 'POST'])
def create_new_item():
    '''Display the page to create a new item for GET requests.
       In case of POST requests, try to add a new item to the database
       with the  values passed in the form fields. If item is successfully
       added to the database, flash success message and redirect to the
       item category page. If not, rollback the changes, flash an error
       message, and display the page to create a new item '''
    if request.method == 'POST':
        item = Item(name=request.form['name'],
                    description=request.form['description'],
                    category_id=request.form['category_id'])
        db_session.add(item)
        try:
            db_session.commit()
            flash('item successfully created')
            return redirect(url_for('show_category',
                                    category_name=item.category.name))
        except IntegrityError as e:
            db_session.rollback()
            flash('item not created due to error: ' + e.args[0])
    categories = db_session.query(Category).all()
    return render_template('create_new_item.html', categories=categories)


@app.route('/catalog/<category_name>/<item_name>/edit',
           methods=['GET', 'PUT'])
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
    try:
        category = (db_session.query(Category)
                    .filter_by(name=category_name).one())
        try:
            item = (db_session.query(Item)
                    .filter_by(name=item_name, category_id=category.id).one())
            if request.method == 'PUT':
                if request.form['name']:
                    item.name = request.form['name']
                if request.form['description']:
                    item.description = request.form['description']
                if request.form['category_id']:
                    item.category_id = request.form['category_id']
                db_session.add(item)
                try:
                    db_session.commit()
                    flash('item successfully edited')
                    return redirect(url_for('show_category',
                                            category_name=item.category.name))
                except IntegrityError as e:
                    db_session.rollback()
                    flash('item not edited due to error: ' + e.args[0])
        except NoResultFound:
            flash('error: no item {} found'.format(item_name))
            return redirect(url_for('show_category',
                                    category_name=category.name))
    except NoResultFound:
        flash('error: no category {} found'.format(category_name))
        return redirect(url_for('show_catalog'))
    categories = db_session.query(Category).all()
    return render_template('edit_item.html',
                           item=item,
                           categories=categories)


@app.route('/catalog/<category_name>/<item_name>/delete',
           methods=['GET', 'DELETE'])
def delete_item(category_name, item_name):
    '''Try to find a item in the database whose name and category name match
       the uri. If no category or item is found, flash an error message and
       redirect to the catalog or category page, respectively.
       If a match is found, display the page to delete this item for
       a GET request. In the case of a DELETE request, delete item from
       database, flash a success message, and redirect to the item category
       page.'''
    try:
        category = (db_session.query(Category)
                    .filter_by(name=category_name).one())
        try:
            item = (db_session.query(Item)
                    .filter_by(name=item_name, category_id=category.id).one())
            if request.method == 'DELETE':
                category = item.category
                db_session.delete(item)
                db_session.commit()
                flash('item successfully deleted')
                return redirect(url_for('show_category',
                                        category_name=category.name))
        except NoResultFound:
            flash('error: no item {} found'.format(item_name))
            return redirect(url_for('show_category',
                                    category_name=category.name))
    except NoResultFound:
        flash('error: no category {} found'.format(category_name))
        return redirect(url_for('show_catalog'))
    categories = db_session.query(Category).all()
    return render_template('delete_item.html',
                           categories=categories,
                           item=item)


def get_category_json(category):
    '''Helper function to obtain all items form a category in JSON'''
    items = db_session.query(Item).filter_by(category_id=category.id).all()
    category_json = category.serialize
    category_json['items'] = [item.serialize for item in items]
    return category_json


# API routing
@app.route('/api/catalog', methods=['GET'])
def show_catalog_API():
    categories = db_session.query(Category).all()
    return jsonify(catalog={'categories': [get_category_json(category)
                                           for category in categories]})


@app.route('/api/catalog/<category_name>', methods=['GET'])
def show_category_API(category_name):
    '''Try to find a category in the database whose name matches the uri.
       If a match is found, return a json with all the items in the category.
       If no category is found, return a json with an error message.'''
    try:
        category = (db_session.query(Category)
                    .filter_by(name=category_name).one())
        return jsonify(Category=get_category_json(category))
    except NoResultFound:
        return (jsonify(Error="no category '{}' found".format(category_name)),
                404)


@app.route('/api/catalog/<category_name>/<item_name>', methods=['GET'])
def show_item_API(category_name, item_name):
    '''Try to find a item in the database whose name and category name match
       the uri. If a match is found, return a json corresponding to the item.
       If no category or item is found, return a json with an error message.'''
    try:
        category = (db_session.query(Category)
                    .filter_by(name=category_name).one())
        try:
            item = (db_session.query(Item)
                    .filter_by(name=item_name, category_id=category.id).one())
            return jsonify(Item=item.serialize)
        except NoResultFound:
            return jsonify(Error="no item '{}' found".format(item_name)), 404
    except NoResultFound:
        return (jsonify(Error="no category '{}' found".format(category_name)),
                404)


@app.route('/api/catalog/new', methods=['POST'])
def create_new_item_API():
    '''Try to find a category in the database whose name matches the request
       parameters. If no category or item is found, return a json with an
       error message. If a category is found, try to add a new item to the
       database with the the request parameters. If item is successfully
       added to the database, return a json corresponding to the item.
       If not, rollback the changes and return a json with an error
       message.'''
    try:
        category = db_session.query(Category).filter_by(
                name=request.args.get('category_name')
            ).one()
        item = Item(name=request.args.get('name'),
                    description=request.args.get('description'),
                    category_id=category.id)
        db_session.add(item)
        try:
            db_session.commit()
            return jsonify(Item=item.serialize)
        except IntegrityError as e:
            db_session.rollback()
            return jsonify(Error=e.args[0]), 400
    except NoResultFound:
        return jsonify(Error="no category '{}' found".format(
                request.args.get('category_name')
            )), 404


@app.route('/api/catalog/<category_name>/<item_name>/edit', methods=['PUT'])
def edit_item_API(category_name, item_name):
    '''Try to find a item in the database whose name and category name match
       the request parameters. If no category or item is found, return a
       json with an error message. If a match is found, try to update the
       item in the database with the values passed in the request. If
       item is successfully updated, return a json corresponding to the
       item. If not, rollback the changes and return a json with an error
       message.'''
    try:
        category = (db_session.query(Category)
                    .filter_by(name=category_name).one())
        try:
            item = (db_session.query(Item)
                    .filter_by(name=item_name, category_id=category.id).one())
            if 'name' in request.args:
                item.name = request.args['name']
            if 'description' in request.args:
                item.description = request.args['description']
            if 'category_id' in request.args:
                item.category_id = request.args['category_id']
            db_session.add(item)
            try:
                db_session.commit()
                return jsonify(Item=item.serialize)
            except IntegrityError as e:
                db_session.rollback()
                return jsonify(Error=e.args[0]), 400
        except NoResultFound:
            return jsonify(Error="no item '{}' found".format(item_name)), 404
    except NoResultFound:
        return (jsonify(Error="no category '{}' found".format(category_name)),
                404)


@app.route('/api/catalog/<category_name>/<item_name>/delete',
           methods=['DELETE'])
def delete_item_API(category_name, item_name):
    '''Try to find a item in the database whose name and category name match
       the request parameters. If no category or item is found, return a
       json with an error message. If a match is found, delete item
       from database and return a json with a success message.'''
    try:
        category = (db_session.query(Category)
                    .filter_by(name=category_name).one())
        try:
            item = (db_session.query(Item)
                    .filter_by(name=item_name, category_id=category.id).one())
            db_session.delete(item)
            db_session.commit()
            return jsonify(Success='item deleted')
        except NoResultFound:
            return jsonify(Error="no item '{}' found".format(item_name)), 404
    except NoResultFound:
        return (jsonify(Error="no category '{}' found".format(category_name)),
                404)


@app.errorhandler(404)
def not_found(message):
    flash(message)
    return render_template('error.html'), 404


if __name__ == '__main__':
    # TODO: change secret key
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
