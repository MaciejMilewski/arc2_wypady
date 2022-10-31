import os

from flask import Flask, request
# CORS do testowania lokalnie
from flask_cors import CORS, cross_origin
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import generate_password_hash, check_password_hash
from google.cloud import datastore

app = Flask(__name__)
#  - CORS do testowania lokalnie
# CORS_ALLOW_ORIGIN="*,*"
# CORS_EXPOSE_HEADERS="*,*"
# CORS_ALLOW_HEADERS="content-type,*"
# cors = CORS(app, origins=CORS_ALLOW_ORIGIN.split(","), allow_headers=CORS_ALLOW_HEADERS.split(",") , expose_headers= CORS_EXPOSE_HEADERS.split(","),   supports_credentials = True)
# app.config['CORS_HEADERS'] = 'Content-Type'

auth = HTTPBasicAuth()
datastore_client = datastore.Client()

users = {}


@app.route('/register', methods=['POST'])
@cross_origin()
def register():
    print(request.args)
    username = request.json['email']
    password = request.json['password']
    if username in users:
        return "There is a user with this email", 409
    else:
        # Store locally username and password
        user = {username: username, password: generate_password_hash(password)}
        users[user[username]] = user[password]
        # Store username in datastore
        kind = "Users"
        name = username
        # user_key = datastore_client.key(kind,name)
        # userKind = datastore.Entity(key=user_key)
        # userKind["username"] = username
        # Save the entity
        # datastore_client.put(userKind)
        return "Pomyślnie zarejestrowano!", 200


@app.route('/login', methods=['POST'])
@cross_origin()
def login():
    username = request.json['email']
    password = request.json['password']
    if username in users:
        # Sprawdź czy podane dane są prawidłowe
        user = verify_password(username, password)
        userObj = {"email": user, "password": password}
        return userObj
    else:
        return "User not found", 404


@auth.verify_password
def verify_password(username, password):
    if username in users and check_password_hash(users.get(username), password):
        return username



@app.route('/')
@auth.login_required
def index():
    kind = "Food"
    name = "Spaghetti_1"
    food_key = datastore_client.key(kind, name)
    food = datastore.Entity(key=food_key)
    food['description'] = "Firestore jest jak spaghetti"
    food['name'] = "Spaghetti"
    datastore_client.put(food)
    return "Wypadaj, {}!".format(auth.current_user())


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 8848)))
