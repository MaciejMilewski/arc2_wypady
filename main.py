import os

from flask import Flask
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import generate_password_hash, check_password_hash
from google.cloud import datastore

app = Flask(__name__)
auth = HTTPBasicAuth()
datastore_client = datastore.Client()

users = {}


@app.route('/register')
def register(username, password):
    if username in users:
        return 409
    else:
        user = {}
        user.username = username
        user.password = generate_password_hash(password)
        pass


@app.route('/')
def index():
    return 'Wypadaj.pl'


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 8848)))
