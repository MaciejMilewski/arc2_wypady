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
from google.cloud import exceptions
# Import google cloud vision
import json
from google.cloud import vision
from concurrent.futures import TimeoutError

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

timeout = 5.0


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
    datastore_client.delete(user[0])
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

    if image.content_length > 500000:
        return "Image is too big", 400
    else:
        if allowed_file(image.filename):

            # Store image file in Google Cloud Storage
            gcs = storage.Client()
            bucket = gcs.get_bucket("staging.wypady.appspot.com")
            blob = bucket.blob("food/" + image.filename)

            content = image.read()
            blob.upload_from_string(content, content_type=image.content_type)

            # Get restaurant entity from Datastore
            restaurant = request.form.get("restaurant")
            restaurant_name_key = datastore_client.key("Restaurant", restaurant)
            restaurant_entity = datastore_client.get(restaurant_name_key)

            if not restaurant_entity:
                return "There is no restaurant", 404
            else:
                # Save Food entity to Datastore
                restaurant_key = datastore_client.key(kind)
                menu = datastore.Entity(key=restaurant_key)
                menu['name'] = name
                menu['description'] = description
                menu['price'] = price
                menu['restaurantKey'] = restaurant_name_key
                menu['image'] = image.filename
                datastore_client.put(menu)

                # Pub/Sub to check if food image is acceptable (image contains food + no forbidden content)
                publisher = pubsub_v1.PublisherClient()
                topic_path = 'projects/wypady/topics/isImageFood'

                data = base64.b64encode(b'')
                future = publisher.publish(topic=topic_path, data=data, filename=image.filename,
                                           description=description, name=name)
                print(f'published message id {future.result()}')

                return 'New food added', 200
        else:
            return 'Only png, jpg images are allowed!', 400


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

        last_letter_index = len(food_prefix) - 1
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
        new_prefix = new_prefix[:len(new_prefix) - 1] + new_last_letter

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


def add_food_to_restaurant_func(item, restaurant_name_key):
    restaurant_key = datastore_client.key("Food")

    menu = datastore.Entity(key=restaurant_key)
    menu['name'] = item['name']
    menu['description'] = item['description']
    menu['price'] = item['price']
    menu['restaurantKey'] = restaurant_name_key
    datastore_client.put(menu)


@app.route('/addMenuFromCSV', methods=['POST'])
def add_menu_from_csv():
    envelope = json.loads(request.data.decode('utf-8'))
    menu_object = json.loads(base64.b64decode(envelope['message']['data']))

    print(f'menu object {menu_object}')

    restaurant_name = menu_object["restaurant"][0:-4]
    print(f'restaurant {restaurant_name}')

    for item in menu_object["menu"]:
        restaurant_key = datastore_client.key('Restaurant', restaurant_name)
        restaurant_entity = datastore_client.get(restaurant_key)
        if restaurant_entity is None:
            new_restaurant = datastore.Entity(key=restaurant_key)
            new_restaurant['name'] = restaurant_name
            datastore_client.put(new_restaurant)
        restaurant_name_key = datastore_client.key("Restaurant", restaurant_name)
        add_food_to_restaurant_func(item, restaurant_name_key)

    return 'OK', 200


def restaurant_exists(restaurant_name):
    restaurant_key = datastore_client.key('Restaurant', restaurant_name)
    restaurant_entity = datastore_client.get(restaurant_key)
    if restaurant_entity is None:
        return False
    return True


@app.route('/likeRestaurant', methods=['POST'])
@auth.login_required
def user_likes_restaurant():
    restaurant_name = request.form.get("name")
    user = auth.current_user()

    with datastore_client.transaction():
        try:
            if restaurant_exists(restaurant_name):

                kind = "Likes"
                like_key = datastore_client.key(kind, restaurant_name + "_" + user)
                like_entity = datastore.Entity(like_key)

                like_entity["username"] = user
                like_entity["restaurantName"] = restaurant_name
                like_entity["value"] = 1
                datastore_client.put(like_entity)
        except exceptions.Conflict:
            return 'Conflict - user likes restaurant', 400

    return 'OK', 200


@app.route('/dislikeRestaurant', methods=['POST'])
@auth.login_required
def user_dislikes_restaurant():
    restaurant_name = request.form.get("name")
    user = auth.current_user()

    with datastore_client.transaction():
        try:
            if restaurant_exists(restaurant_name):
                kind = "Likes"
                like_key = datastore_client.key(kind, restaurant_name + "_" + user)
                like_entity = datastore.Entity(like_key)
                like_entity["username"] = user
                like_entity["restaurantName"] = restaurant_name
                like_entity["value"] = -1
                datastore_client.put(like_entity)
        except exceptions.Conflict:
            return 'Conflict - user dislikes restaurant', 400

    return 'OK', 200


@app.route('/restaurantLikes', methods=['GET'])
@auth.login_required
def get_restaurant_likes():
    restaurant_name = request.args.get("name")
    is_like = request.args.get("like")

    kind = "Likes"
    query = datastore_client.query(kind=kind)
    query.add_filter('restaurantName', '=', restaurant_name)
    if is_like == "like":
        query.add_filter('value', '=', 1)
    elif is_like == "dislike":
        query.add_filter('value', '=', -1)
    result = query.keys_only()
    print("Result keys_only: ", result)
    return "", 200

    if len(result) == 0:
        return "Restaurant not found in likesCounter", 404

    restaurant_counter = []
    for entity in result:
        restaurant_counter.append({
            "restaurantName": entity["restaurantName"],
            "likes": entity["likes"],
            "dislikes": entity["dislikes"]
        })

    return restaurant_counter, 200


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 8848)))
