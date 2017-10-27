#!/usr/bin/env python3
'''Catalog app controllers.'''
from sqlalchemy.exc import IntegrityError
from flask import (request, render_template, redirect, url_for, flash, jsonify,
                   g, session)

from models import Item, Category
from helpers import (allowed_file, clear_session, error_message,
                     login_required, update_item, create_item)
from app import app, db_session


@app.before_request
def normalize_request_parameters():
    '''Get parameters from POST and PUT requests.'''
    if request.method in ['PUT', 'POST']:
        content_type = request.headers.get('Content-Type')

        if request.is_json:
            category_id = request.get_json().get('category_id')
            name = request.get_json().get('name')
            description = request.get_json().get('description')
            image = None

        elif 'multipart/form-data' in content_type:
            category_id = request.form.get('category_id')
            name = request.form.get('name')
            description = request.form.get('description')
            image = request.files.get('image')

        elif 'application/x-www-form-urlencoded' in content_type:
            category_id = request.args.get('category_id')
            name = request.args.get('name')
            description = request.args.get('description')
            image = None

        else:
            return jsonify(Error='Invalid Content-Type'), 400

        # If parameters are present save them into g object
        g.params = {}
        if name and name != '':
            g.params['name'] = name

        if description and description != '':
            g.params['description'] = description

        if category_id and category_id != '':
            g.params['category_id'] = category_id

        if image and allowed_file(image.filename):
            g.params['image'] = image


@app.route('/login', methods=['GET'])
def show_login():
    return render_template('oauth/login.html')


@app.route('/logout')
def disconnect():
    clear_session()
    flash('You have been logged out', 'alert-success')
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
                create_item(session['user_id'])
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
                                       categories=categories, max_file_size=(
                                        app.config['MAX_CONTENT_LENGTH']))

            elif request.method == 'POST':
                try:
                    update_item(item)
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


@app.errorhandler(404)
@app.errorhandler(413)
def handle_http_error(error):
    '''Return page not found or request too large error pages.'''
    return render_template('error.html', message=error), error.code
