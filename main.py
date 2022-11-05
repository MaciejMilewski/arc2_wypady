import os

from flask import Flask, request
from flask_cors import CORS, cross_origin
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import generate_password_hash, check_password_hash
from google.cloud import datastore

app = Flask(__name__)
#  - CORS do testowania lokalnie
CORS_ALLOW_ORIGIN = "*,*"
CORS_EXPOSE_HEADERS = "*,*"
CORS_ALLOW_HEADERS = "content-type,*"
cors = CORS(app, origins=CORS_ALLOW_ORIGIN.split(","), allow_headers=CORS_ALLOW_HEADERS.split(","),
            expose_headers=CORS_EXPOSE_HEADERS.split(","), supports_credentials=True)
app.config['CORS_HEADERS'] = 'Content-Type'

auth = HTTPBasicAuth()
datastore_client = datastore.Client()


def search_by_email(list_of_users, email):
    for user in list_of_users:
        print("Checking the user:")
        print(user)
        if user['email'] == email:
            return user
        else:
            continue
    return False


@app.route('/register', methods=['POST'])
@cross_origin()
def register():
    print(request.args)
    username = request.json['email']
    password = request.json['password']
    query = datastore_client.query(kind='Users')
    query.add_filter('email', '=', username)
    user = list(query.fetch())
    print(user)
    print(len(user))

    if len(user) != 0:
        return "There is a user with this email", 409
    else:
        # Datastore -> save user
        kind = "Users"
        name = username
        user_key = datastore_client.key(kind, name)
        user = datastore.Entity(key=user_key)
        user['email'] = username
        user['password'] = generate_password_hash(password)
        datastore_client.put(user)

        return "Pomyślnie zarejestrowano!", 200


@app.route('/login', methods=['POST'])
@cross_origin()
def login():
    username = request.json['email']
    password = request.json['password']
    users = list(datastore_client.query(kind='Users').fetch())
    print(users)
    print("Użytkownicy ^")
    user = search_by_email(users, username)
    if user is not False:
        user_verified = verify_password(user, password)
        if user_verified is not False:
            user_obj = {"email": user_verified['email'], "password": user_verified['password']}
            return user_obj
        else:
            return "Password don't match", 403
    else:
        return "User not found", 404


@auth.verify_password
def verify_password(user, password):
    print("Veryfication of password")
    if check_password_hash(user['password'], password):
        return user
    else:
        return False


@app.route('/')
@auth.login_required
def index():
    return "Wypadaj, {}!".format(auth.current_user())


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 8848)))
