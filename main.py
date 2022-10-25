import os

from flask import Flask, request
from flask_cors import CORS, cross_origin
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import generate_password_hash, check_password_hash
from google.cloud import datastore

app = Flask(__name__)
cors = CORS(app)
app.config['CORS_HEADERS'] = 'Content-Type'
auth = HTTPBasicAuth()
# datastore_client = datastore.Client()

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
        user = {username: username, password: generate_password_hash(password)}
        users[user[username]] = user[password]
        return users


@app.route('/')
def index():
    return 'Wypadaj.pl'


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 8848)))
