# Catalog App

Source code for my fourth project for the [Full Stack Web Developer Nanodegree](https://www.udacity.com/course/full-stack-web-developer-nanodegree--nd004) (FSWDN) program from Udacity.

This project is a web application that provides a list of items within a variety of categories and integrate third party user registration and authentication via OAuth 1.0 and 2.0 The web app also provides API endpoints to access/edit the same information as displayed in the HTML endpoints for an arbitrary item in the catalog.

## Table of Contents
* [Installation](#Installation)
* [Requirements](#Requirements)
* [API Endpoints](#API_Endpoints)
  * [Fetch Entire Catalog](#Fetch_Entire_Catalog)
  * [Fetch Category](#Fetch_Category)
  * [Fetch Item](#Fetch_Item)
  * [Create Item](#Create_Item)
  * [Edit Item](#Edit_Item)
  * [Delete Item](#Delete_Item)

## Installation

Clone or download the repository on your computer.
Create a file called for example *local_config.py*. Copy and paste in it the following and update with your own settings:
```
# App secret key
SECRET_KEY='your_app_secret_key'

# OAuth credentials
OAUTH_CREDENTIALS = {
    'google': {
        'client_id': 'your_google_client_id',
        'client_secret': 'your_google_client_secret'
    },
    'facebook': {
        'client_id': ''your_facebook_client_id'',
        'client_secret': 'your_facebook_client_secret'
    },
    'github':  {
        'client_id': 'your_github_client_id',
        'client_secret': 'your_github_client_secret'
    },
    'linkedin': {
        'client_id': 'your_linkedin_client_id',
        'client_secret': 'your_linkedin_client_secret'
    },
    'twitter': {
        'consumer_key': 'your_twitter_consumer_key',
        'consumer_secret': 'your_twitter_consumer_secret'
    }
}
```
If you need to override any settings from *default_settings.py* do so in *local_config.py*.
You must then set the environment variable *APPLICATION_SETTINGS* to the file path:
`export APPLICATION_SETTINGS=/path/to/local_config.py`
Run `python models.py` to create the database and `python application.py` to start the webserver. Access the app in your web browser at `http://localhost:5000/`.
Optionally you can run `python db_seed.py` to populate the database with random placeholder items. Edit the *db_seed.py* file with your own email address if you want to be able to edit or delete those items.

### OAuth Set Up

Go to your (or create a new) developer account with each of the OAuth provider and create a new web app. Update *local_config.py* with the client ID and client secret (or consumer key and consumer secret) of the new app.
Set the callback uri to `http://localhost:5000/oauth2callback/:provider`. Twitter uses OAuth 1.0, the callback uri in this case should be: `http://localhost:5000/oauth1callback/twitter`.

## Requirements

You will need [SQLite](https://www.sqlite.org) and [Python](https://www.python.org) installed on your computer as well as the following Python libraries:
* [SQLAlchemy](http://www.sqlalchemy.org)
* [Flask](http://flask.pocoo.org)
* [Flask-SeaSurf](http://flask-seasurf.readthedocs.io)
* [Requests](http://docs.python-requests.org)
* [Requests-OAuthlib](http://requests-oauthlib.readthedocs.io)
* [itsdangerous](http://pythonhosted.org/itsdangerous/)

## API Endpoints
The catalog API provides methods for accessing a resource such as an item or a category. POST, PUT and DELETE requests require an authorization token (valid for 1 hour) that can be obtained at http://localhost:5000/token once you are signed in.
(The following is inspired from this [template](https://gist.github.com/iros/3426278))

---
### Fetch Entire Catalog

* **URL** catalog/api/v1.0/items

* **Method:** `GET`

* **Success Response:**

  * **Code:** 200 <br />
    **Content:**
    `{
  "catalog": {
    "categories": [
      {
        "id": 14,
        "items": [
          {
            "category_id": 14,
            "description": "Lorem ipsum do...",
            "id": 40,
            "image_url": "/static/img/uploads/image1.jpg",
            "name": "Sociosqu",
            "user_id": 1
          },
          {
            "category_id": 14,
            "description": "Lorem ipsum do...",
            "id": 80,
            "image_url": "/static/img/uploads/image2.jpg",
            "name": "Integer",
            "user_id": 3
          }
        ],
        "name": "Aenean"
      },
      ...,
      {
        "id": 3,
        "items": [
          {
            "category_id": 3,
            "description": "Lorem ipsum do...",
            "id": 20,
            "image_url": "/static/img/uploads/image8.jpg",
            "name": "Blandit",
            "user_id": 1
          },
          ...,
          {
            "category_id": 3,
            "description": "Lorem ipsum do...",
            "id": 39,
            "image_url": "/static/img/uploads/image9.jpg",
            "name": "Vestibulum",
            "user_id": 10
          }
        ],
        "name": "Aliquam"
      },
    ]
  }
}`

* **Sample Call:** `curl -X GET http://localhost:5000/catalog/api/v1.0/items`

----
### Fetch Category

* **URL** catalog/api/v1.0/:category

* **Method:** `GET`

*  **URL Params**

   **Required:**

   `category=[string]`

* **Success Response:**

  * **Code:** 200 <br />
    **Content:**
    `{
  "Category": {
    "id": 14,
    "items": [
      {
        "category_id": 14,
        "description": "Lorem ipsum do...",
        "id": 40,
        "image_url": "/static/img/uploads/image1.jpg",
        "name": "Sociosqu",
        "user_id": 10
      },
      ...,
      {
        "category_id": 14,
        "description": "Lorem ipsum do...",
        "id": 80,
        "image_url": "/static/img/uploads/image2.jpg",
        "name": "Integer",
        "user_id": 1
      }
    ],
    "name": "Aenean"
  }
}`

* **Error Response:**

  * **Code:** 404 NOT FOUND <br />
    **Content:**
    `{ "Error": "no category 'category_name' found" }`

* **Sample Call:** `curl -X GET http://localhost:5000/catalog/api/v1.0/category_name`

----
### Fetch Item

* **URL** catalog/api/v1.0/:category/:item

* **Method:** `GET`

*  **URL Params**

   **Required:**

```
     category=[string]
     item=[string]
```

* **Success Response:**

  * **Code:** 200 <br />
    **Content:**
    `{
  "Item": {
    "category_id": 14,
    "description": "Lorem ipsum do...",
    "id": 40,
    "image_url": "/static/img/uploads/image.jpg",
    "name": "Sociosqu",
    "user_id": 10
  }
}`

* **Error Response:**

  * **Code:** 404 NOT FOUND <br />
    **Content:**
    `{ "Error": "no item 'item_name' found" }`
    **or** `{ "Error": "no category 'category_name' found" }`

* **Sample Call:** `curl -X GET http://localhost:5000/catalog/api/v1.0/category_name/item_name`

----
### Create A New Item

* **URL** catalog/api/v1.0/items

* **Method:** `POST`

* **Data Params**

   **Required:**

    ```
     name=[string]
     category_id=[integer]
    ```

   **Optional:**

    ```
     description=[string]
     image=[file]
    ```

* **Success Response:**

  * **Code:** 200 <br />
    **Content:**
    `{
    "Item": {
        "category_id": 14,
        "description": "Lorem ipsum do..",
        "id": 64,
        "image_url": "/static/img/uploads/image.jpg",
        "name": "Sociosqu",
        "user_id": 1
    }
}`

* **Error Response:**

  * **Code:** 401 UNAUTHORIZED <br />
    **Content:**
    `{ "Error" : "Missing authorization credentials" }`
    **or** `{ "Error" : "Wrong authorization type" }`
    **or** `{ "Error" : "Wrong authorization token" }`

  * **Code:** 404 NOT FOUND <br />
    **Content:**
    `{ "Error" : "User id not found" }`

  * **Code:** 422 UNPROCESSABLE ENTRY <br />
    **Content:**
    `{ "Error": "(sqlite3.IntegrityError) UNIQUE constraint failed: item.name, item.category_id" }`
    **or** `{ "Error": "(sqlite3.IntegrityError) CHECK constraint failed: item" }`

* **Sample Call:**

    ```
    curl -X POST http://localhost:5000/catalog/api/v1.0/items \
      -H 'authorization: Bearer some_token' \
      -H 'content-type: multipart/form-data; boundary=----Boundary' \
      -F 'name=Item name' \
      -F 'description=Lorem ipsum do...' \
      -F category_id=1 \
      -F 'image=@Path_to_image_file'
    ```

   or if no image is uploaded, *x-www-form-urlencoded* can be used:

    ```
    curl -X POST http://localhost:5000/catalog/api/v1.0/items \
      -H 'authorization: Bearer some_token' \
      -H 'content-type: application/x-www-form-urlencoded' \
      -d 'name=Item%20name&description=Lorem%20ipsum%20do...&category_id=1'
    ```

----
### Edit Item

* **URL** catalog/api/v1.0/:category/:item

* **Method:** `PUT`

* **Data Params**

   **Optional:**

    ```
     name=[string]
     description=[string]
     category_id=[integer]
     image=[file]
    ```

* **Success Response:**

  * **Code:** 200 <br />
    **Content:**
    `{
    "Item": {
        "category_id": 14,
        "description": "Lorem ipsum do..",
        "id": 64,
        "image_url": "/static/img/uploads/image.jpg",
        "name": "Sociosqu",
        "user_id": 1
        }
    }`

* **Error Response:**

  * **Code:** 401 UNAUTHORIZED <br />
    **Content:**
    `{ "Error" : "Missing authorization credentials" }`
    **or** `{ "Error" : "Wrong authorization type" }`
    **or** `{ "Error" : "Wrong authorization token" }`
    **or** `{ "Error" : "You are not authorized to edit this item"}`

  * **Code:** 404 NOT FOUND <br />
    **Content:**
    `{ "Error" : "User id not found" }`

  * **Code:** 422 UNPROCESSABLE ENTRY <br />
    **Content:**
    `{ "Error": "(sqlite3.IntegrityError) UNIQUE constraint failed: item.name, item.category_id" }`
    **or** `{ "Error": "(sqlite3.IntegrityError) CHECK constraint failed: item" }`

* **Sample Call:**

    ```
    curl -X PUT http://localhost:5000/catalog/api/v1.0/category_name/item_name \
      -H 'authorization: Bearer some_token' \
      -H 'content-type: multipart/form-data; boundary=----Boundary' \
      -F 'name=Item name' \
      -F 'description=Lorem ipsum do...' \
      -F category_id=1 \
      -F 'image=@Path_to_image_file'
    ```

   or if no image is uploaded, *x-www-form-urlencoded* can be used:

    ```
    curl -X PUT http://localhost:5000/catalog/api/v1.0/category_name/item_name \
      -H 'authorization: Bearer some_token' \
      -H 'content-type: application/x-www-form-urlencoded' \
      -d 'name=Item%20name&description=Lorem%20ipsum%20do...&category_id=1'
    ```

----
### Delete Item

* **URL** catalog/api/v1.0/:category/:item

* **Method:** `DELETE`

* **Success Response:**

  * **Code:** 200 <br />
    **Content:**
    `{ "Success": "item deleted" }`

* **Error Response:**

  * **Code:** 401 UNAUTHORIZED <br />
    **Content:**
    `{ "Error" : "Missing authorization credentials" }`
    **or** `{ "Error" : "Wrong authorization type" }`
    **or** `{ "Error" : "Wrong authorization token" }`
    **or** `{ "Error" : "You are not authorized to delete this item"}`

  * **Code:** 404 NOT FOUND <br />
    **Content:**
    `{ "Error" : "User id not found" }`

* **Sample Call:**

    ```
    curl -X DELETE http://localhost:5000/catalog/api/v1.0/category_name/item_name \
      -H 'authorization: Bearer some_token' \
    ```

