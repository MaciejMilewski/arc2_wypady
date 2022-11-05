import os

from flask import Flask, request
from flask_cors import CORS, cross_origin
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import generate_password_hash, check_password_hash
from google.cloud import datastore
from google.cloud import storage

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

# Image allowed extensions
ALLOWED_EXTENSIONS = {'jpg', 'png'}


def allowed_file(fname):
    return '.' in fname and \
           fname.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


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

    user_key = datastore_client.key('Users', username)
    user_entity = datastore_client.get(user_key)
    if user_entity is not None:
        user_verified = verify_password(user_entity, password)
        if user_verified is not False:
            user_obj = {"email": user_verified['email'], "password": user_verified['password']}
            return user_obj
        else:
            return "Password don't match", 403
    else:
        return "User not found", 404


@auth.verify_password
def verify_password(user, password):
    print(type(user))
    print(user)
    print("Veryfication of password")
    if type(user) == datastore.Entity:
        if check_password_hash(user['password'], password):
            return user
        else:
            return False
    elif type(user) == str:
        user_key = datastore_client.key('Users', user)
        user_entity = datastore_client.get(user_key)
        print("User Entity:")
        print(user_entity)
        if user_entity is not None:
            return user_entity['email']
        else:
            return False
    else:
        return False


@app.route('/')
@auth.login_required
def index():
    return "Wypadaj, {}!".format(auth.current_user())


@app.route('/addNewRestaurant', methods=['POST'])
@auth.login_required
def addNewRestaurant():
    # print(request.json)
    name = request.json['name']
    image = request.json['file']
    print(image)

    if image.getSize() > 500000:
        return "Image is too big", 403
    else:
        restaurant_key = datastore_client.key('Restaurant', name)
        restaurant_entity = datastore_client.get(restaurant_key)
        if restaurant_entity is not None:
            return 'There is a restaurant with this name', 409
        else:

            new_restaurant = datastore.Entity(key=restaurant_key)
            new_restaurant['name'] = name

            # Storage bucket
            # Create a Cloud Storage client.
            # gcs = storage.Client()

            # Get the bucket that the file will be uploaded to.
            # bucket = gcs.get_bucket("staging.wypady.appspot.com")

            # new_restaurant['image'] = image
            datastore_client.put(new_restaurant)
            return 'New restaurant added', 200


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 8848)))
