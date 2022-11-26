import base64
import os
import io
from flask import Flask, request
from flask_cors import CORS, cross_origin
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import generate_password_hash, check_password_hash
from google.cloud import datastore
from google.cloud import storage
from google.cloud import pubsub_v1
# Import google cloud vision
from google.cloud import vision

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
    # print(request.args)
    username = request.json['email']
    password = request.json['password']
    query = datastore_client.query(kind='Users')
    query.add_filter('email', '=', username)
    user = list(query.fetch())
    # print(user)
    # print(len(user))

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
            return "Password don't match", 400
    else:
        return "User not found", 404


@auth.verify_password
def verify_password(user, password):
    # print(type(user))
    # print(user)
    # print("Veryfication of password")
    if type(user) == datastore.Entity:
        if check_password_hash(user['password'], password):
            return user
        else:
            return False
    elif type(user) == str:
        user_key = datastore_client.key('Users', user)
        user_entity = datastore_client.get(user_key)
        # print("User Entity:")
        # print(user_entity)
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
def add_new_restaurant():
    # print(request.json)
    name = request.form.get('name')
    image = request.files['file']
    if image.content_length > 500000:
        return "Image is too big", 400
    else:
        if allowed_file(image.filename):
            restaurant_key = datastore_client.key('Restaurant', name)
            restaurant_entity = datastore_client.get(restaurant_key)
            if restaurant_entity is not None:
                return 'There is a restaurant with this name', 409
            else:

                new_restaurant = datastore.Entity(key=restaurant_key)
                new_restaurant['name'] = name

                # Storage bucket
                # Create a Cloud Storage client.
                gcs = storage.Client()
                #
                # Get the bucket that the file will be uploaded to.
                bucket = gcs.get_bucket("staging.wypady.appspot.com")
                blob = bucket.blob("restaurants/" + image.filename)
                blob.upload_from_string(
                    image.read(),
                    content_type=image.content_type)
                new_restaurant['image'] = image.filename
                datastore_client.put(new_restaurant)
                return 'New restaurant added', 200
        else:
            return 'Only png, jpg images are allowed!', 400


@app.route('/addNewFood', methods=['POST'])
@auth.login_required
def add_new_food():
    kind = "Food"
    name = request.form.get("name")
    price = request.form.get("price")
    description = request.form.get("description")
    image = request.files['file']

    # pub sub
    publisher = pubsub_v1.PublisherClient()
    topic_path = 'projects/wypady/topics/isImageFood'

    # data = image.read().encode("utf-8")
    data = base64.b64encode(bytes(str(image.read()), 'utf-8'))

    future = publisher.publish(topic=topic_path, data=data)
    print(f'published message id {future.result()}')

    # Key property
    restaurant = request.form.get("restaurant")
    restaurant_name_key = datastore_client.key("Restaurant", restaurant)

    restaurant_entity = datastore_client.get(restaurant_name_key)

    if not restaurant_entity:
        return "There is no restaurant", 404
    else:
        restaurant_key = datastore_client.key(kind)
        menu = datastore.Entity(key=restaurant_key)
        menu['name'] = name
        menu['description'] = description
        menu['price'] = price
        menu['restaurantKey'] = restaurant_name_key

        # Storage bucket
        # Create a Cloud Storage client.
        gcs = storage.Client()
        #
        # Get the bucket that the file will be uploaded to.
        bucket = gcs.get_bucket("staging.wypady.appspot.com")
        blob = bucket.blob("restaurants/" + image.filename)
        blob.upload_from_string(
            image.read(),
            content_type=image.content_type)
        menu['image'] = image.filename

        datastore_client.put(menu)
        return 'New food added', 200


@app.route('/getFoodByName', methods=['GET'])
@auth.login_required
def get_food_by_name():
    food_prefix = request.args.get("name")
    print("Food prefix = ", food_prefix)

    size = request.args.get("size", 5, type=int)

    if int(size) > 100:
        return "Requested size is too large", 400
    if food_prefix is None:
        return "Prefix should be provided", 400
    if food_prefix.isalpha() is False:
        return "Food prefix contains illegal characters", 400
    if len(food_prefix) < 1:
        return "Food name is too short", 400
    else:
        query = datastore_client.query(kind='Food')
        query.add_filter('name', '>=', str(food_prefix))

        last_letter_index = len(food_prefix)-1
        next_letter = food_prefix[last_letter_index]
        next_letter = bytes(next_letter, 'utf-8')

        print("next_letter[0] = ", next_letter.decode("utf-8"))

        if next_letter.decode("utf-8") == "z":
            new_last_letter = "z"
        elif next_letter.decode("utf-8") == "Z":
            new_last_letter = "Z"
        else:
            new_last_letter = bytes([next_letter[0] + 1])
            new_last_letter = new_last_letter.decode("utf-8")

        new_prefix = food_prefix
        new_prefix = new_prefix[:len(new_prefix)-1] + new_last_letter

        query.add_filter('name', '<', new_prefix)
        result = list(query.fetch(limit=size))
        print(result)

        new_result = {}
        food_list = []
        for food_entity in result:
            food_list.append(food_entity['name'])

        new_result["foods"] = food_list
        return new_result, 200


@app.route('/isImageFood', methods=['POST'])
@auth.login_required
def is_image_food():
    client = vision.ImageAnnotatorClient()

    # Get URI from form
    image = request.files['file']
    if image.filename == '':
        return "Image not found", 400
    if image.content_length > 500000:
        return "Image is too big", 400
    else:
        if allowed_file(image.filename):
            content = image.read()
            image_vision = vision.Image(content=content)
            response_labels = client.label_detection(image=image_vision)
            labels = response_labels.label_annotations

            response_explicit = client.safe_search_detection(image=image_vision)
            safe = response_explicit.safe_search_annotation

            likelihood_name = ('UNKNOWN', 'VERY_UNLIKELY', 'UNLIKELY', 'POSSIBLE',
                               'LIKELY', 'VERY_LIKELY')

            print('adult: {}'.format(likelihood_name[safe.adult]))
            print('medical: {}'.format(likelihood_name[safe.medical]))
            print('spoofed: {}'.format(likelihood_name[safe.spoof]))
            print('violence: {}'.format(likelihood_name[safe.violence]))
            print('racy: {}'.format(likelihood_name[safe.racy]))

            if likelihood_name[safe.adult] != 'UNLIKELY' and likelihood_name[safe.adult] != 'VERY_UNLIKELY':
                return "Adult content", 400
            if likelihood_name[safe.violence] != 'UNLIKELY' and likelihood_name[safe.violence] != 'VERY_UNLIKELY':
                return "Violent content", 400
            if likelihood_name[safe.medical] != 'UNLIKELY' and likelihood_name[safe.medical] != 'VERY_UNLIKELY':
                return "Medical content", 400
            if likelihood_name[safe.spoof] != 'UNLIKELY' and likelihood_name[safe.spoof] != 'VERY_UNLIKELY':
                return "Fake content", 400
            if likelihood_name[safe.racy] != 'UNLIKELY' and likelihood_name[safe.racy] != 'VERY_UNLIKELY':
                return "Racy content", 400

            for label in labels:
                food = label.description.find('food')
                food_c = label.description.find('Food')
                if food != -1 or food_c != -1:
                    return "True", 200

            return "False", 200
        else:
            return 'Invalid format of a file', 400


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 8848)))
