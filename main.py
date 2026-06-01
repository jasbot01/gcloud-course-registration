from flask import Flask, request, jsonify, send_file
from google.cloud import datastore

import requests
import json

from six.moves.urllib.request import urlopen
from jose import jwt
from authlib.integrations.flask_client import OAuth
from google.cloud import storage
import io

app = Flask(__name__)
app.secret_key = 'SECRET_KEY'

client = datastore.Client()

BUCKET = "jas-bucket-final"
LODGINGS = "lodgings"
USERS = "users"
COURSES = "courses"
AVATARS = "avatar"


fields_required = ['subject', 'number', 'title', 'term', 'instructor_id']

# Update the values of the following 3 variables
CLIENT_ID = '3fZOZZVP6LQQTGKn2UGgfPtEMMlIyfo8'
CLIENT_SECRET = 'RRHWA--VLbtvRAhqquNAHNlb8RTMan2jn6VOu-4wTCXVWCpm3ikPotu13Rn1Re6o'
DOMAIN = 'dev-xgmr5ld6eumutqj7.us.auth0.com'
URL = 'https://snydejas-final.wl.r.appspot.com'

ALGORITHMS = ["RS256"]

oauth = OAuth(app)

auth0 = oauth.register(
    'auth0',
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    api_base_url="https://" + DOMAIN,
    access_token_url="https://" + DOMAIN + "/oauth/token",
    authorize_url="https://" + DOMAIN + "/authorize",
    client_kwargs={
        'scope': 'openid profile email',
    },
)

# This code is adapted from https://auth0.com/docs/quickstart/backend/python/01-authorization?_ga=2.46956069.349333901.1589042886-466012638.1589042885#create-the-jwt-validation-decorator

class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


@app.errorhandler(AuthError)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response

# Verify the JWT in the request's Authorization header
def verify_jwt(request):
    if 'Authorization' in request.headers:
        auth_header = request.headers['Authorization'].split()
        token = auth_header[1]
    else:
        raise AuthError({"code": "no auth header",
                            "description":
                                "Authorization header is missing"}, 401)
    
    jsonurl = urlopen("https://"+ DOMAIN+"/.well-known/jwks.json")
    jwks = json.loads(jsonurl.read())
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.JWTError:
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)
    if unverified_header["alg"] == "HS256":
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)
    rsa_key = {}
    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=CLIENT_ID,
                issuer="https://"+ DOMAIN+"/"
            )
        except jwt.ExpiredSignatureError:
            raise AuthError({"code": "token_expired",
                            "description": "token is expired"}, 401)
        except jwt.JWTClaimsError:
            raise AuthError({"code": "invalid_claims",
                            "description":
                                "incorrect claims,"
                                " please check the audience and issuer"}, 401)
        except Exception:
            raise AuthError({"code": "invalid_header",
                            "description":
                                "Unable to parse authentication"
                                " token."}, 401)

        return payload
    else:
        raise AuthError({"code": "no_rsa_key",
                            "description":
                                "No RSA key in JWKS"}, 401)


@app.route('/')
def index():
    return "Please navigate to /lodgings to use this API"\

# Create a lodging if the Authorization header contains a valid JWT
@app.route('/lodgings', methods=['POST'])
def lodgings_post():
    if request.method == 'POST':
        payload = verify_jwt(request)
        content = request.get_json()
        new_lodging = datastore.entity.Entity(key=client.key(LODGINGS))
        new_lodging.update({"name": content["name"], "description": content["description"],
          "price": content["price"]})
        client.put(new_lodging)
        return jsonify(id=new_lodging.key.id)
    else:
        return jsonify(error='Method not recogonized')

# Decode the JWT supplied in the Authorization header
@app.route('/decode', methods=['GET'])
def decode_jwt():
    payload = verify_jwt(request)
    return payload          

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  
#               #1 :   LOGIN USERS AUTH0                            |
#    send req should on success send back token jwt by auth0.       |
#  this sets vals of jwts & sub for each of the 9 users as env var  |
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
@app.route('/' + USERS + '/login', methods=['POST'])
#@app.route(users + '/login', methods=['POST'])
def login_user():
    # get json from incoming request
    content = request.get_json()

    # check if both username and password are present in request body
    if not('username' in content and 'password' in content):
        # return error msg if one or both are missing
        return ({'Error': 'The request body is invalid'}, 400)

    # get the username and password from request
    username = content["username"]
    password = content["password"]

    # set the body that is to be sent in the POST req to oauth
    body = {'grant_type':'password','username':username,
        'password':password,
        'client_id':CLIENT_ID,
        'client_secret':CLIENT_SECRET
        }
    
    # set the content type headers for request to json
    headers = { 'content-type': 'application/json' }

    # construct url for oauth token endpoint 
    url = 'https://' + DOMAIN + '/oauth/token'
    
    # send the post request to oauth endpoint with body and header
    res = requests.post(url, json=body, headers=headers)

    # converts response to json format
    res_data = res.json()

    # if we don't get a response containing id token then 
    # respond with error unauthorized
    if 'id_token' not in res_data:
        return ({'Error': 'Unauthorized'}, 401) 

    # authentication successful set var to this val and return success
    t = {}
    t['token'] = res_data['id_token']
    #return res.text, 200, {'Content-Type':'application/json'}
    return t, 200

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -   
#                       #2 : GET ALL USERS                          |
#  jwt header as bearer token in auth header with users as admin    |
#  returns all 9 users with each propery id, role, sub shown        |
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
@app.route('/' + USERS, methods=['GET'])
def get_users():
    #if 'Authorization' in request.headers:
    #query = client.query(kind=USERS)
    # verify the jwt token and extract the payload
    try:
        payload = verify_jwt(request)
    except:
        return ({"Error": "Unauthorized"}, 401)
    
    # same as finding a business by the owner_id in prev assignment
    # query for admin under datastore kind : users to match the sub val
    # if admin role is found , fetch all users
    # initializes query for the users kind (collection) in datastore
    ad_query = client.query(kind=USERS)
    # filters are searching for users the match fields sub 
    # that was extracted from JWT payload
    ad_query.add_filter('sub', '=', payload['sub'])

    # where the role field is admin
    ad_query.add_filter('role', '=',"admin")

    # fetch performs the query and retrieves *all* matching results
    # using list just forces query to return all results as a list
    results = list(ad_query.fetch())
    
    # if results not empty
    if results:
        # create new query for USERS kind in datastore, fetch all users
        user = client.query(kind=USERS)
        # same thing as previous listing all results
        results = list(user.fetch())

        # look through our results list
        for i in results:
            # each datastore user has unique key (i.key)
            # gets unique identifer assigned by datastore to that identity
            # key valu pair to each user
            # key is 'id' val is the datastore unique id (i.key.id)
            i['id'] = i.key.id
        return results, 200
    
    else:
        return ({"Error": "You don't have permission on this resource"}, 403)

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -   
#                       #3 : GET A USER                             |
#  if user has an avatar, body must also include propery avatar url |    
#  response will include differing properties depending on role such|
#  as instructor or student under property: courses                 |        
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
@app.route('/' + USERS + '/<int:id>', methods=['GET'])
def get_a_user(id):
    try:
        #check incoming request for valid json web token
        payload = verify_jwt(request)
    except:
        # error handling if jwt is not valid
        return ({'Error': 'Unauthorized'}, 401)

    # here we get the users information
    # client key creates a reference to the user entity using 
    # USERS kind and the id
    user_key = client.key(USERS, id)
    # fetches user entity from database
    user = client.get(key=user_key)
    # add id of user to user data
    user['id'] = user.key.id

    # if no user is found then return an error
    if user is None:
        return ({'Error'}, 404)
    
    # fetch avatar information 
    avatar_query = client.query(kind=AVATARS)
    # create query and filter by student_id matching id of the user
    avatar_query.add_filter('student_id', '=', user.key.id)
    # list of avatars found that match the user
    avatar_results = list(avatar_query.fetch())

    # if the role of the user is a student then an empty
    # list of courses will be initialized
    if user['role'] == 'student':
        user['courses'] = []

        # then using enrollment to filter through courses datastore
        course_query = client.query(kind=COURSES)
        
        #    #      #         # C O N C I D E R USING IN OPERATOR       #       #      #
    # # # # #   #   #   #   #   #   #   #   #   #   #   
        course_query.add_filter('enrollment', '=', user.key.id)
        results = list(course_query.fetch())

        # if user has an avatar then it'll add avatar_url field
        # to the user object which links to avatar img
        if len(avatar_results) != 0:
            user['avatar_url'] = URL + '/' + USERS + '/' + str(id) + '/avatar'

        for course in results:
            user['courses'].append(course.key.id)
        
    # if user has the role of instructor it will query courses kind
    # filtering on the instructor_id which are courses that are
    # taught by the instructor
    if user['role'] == 'instructor':
        # shoulder display empty array if instructor isn't teaching
        user['courses'] = []
        course_query = client.query(kind=COURSES)
        course_query.add_filter('instructor_id', '=', id)
        results = list(course_query.fetch())

        for course in results:
            course_url = URL + '/' + DOMAIN + '/' + COURSES + '/' + str(course.key.id)
            # this appends the url of each course to the courses list for the
            # instructor
            user['courses'].append(course_url)
    
    # payload sub is associated with the jwt token
    # if sub token matches with sub of user user data returned
    # with 200 OK status
    if payload['sub'] == user['sub']:
        return user, 200
    else:
        user_query = client.query(kind=USERS)
        # otherwise, check if user is an admin querying
        # for users with sam sub and role of admin
        user_query.add_filter('sub', '=', payload['sub'])
        user_query.add_filter('role', '=', 'admin')

        results = list(user_query.fetch())

        if results:
            return user, 200
        else:
            return ({'Error': 'You don\'t have permission on this resource'}, 403)

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -   
#                       #4 : CREATE/UPDATE AVATAR                   |
#  if user has an avatar, body must also include propery avatar url |    
#  response will include differing properties depending on role such|
#  as instructor or student under property: courses                 |        
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
def list_my_blobs(bucket_name):
    # creates client instance that will interact with google cloud storage
    storage_client = storage.Client()
    blobs = storage_client.list_blobs(bucket_name)
    return blobs

def is_the_user(sub, id):
    # checks if sub matches sub value of user with id in datastore
    # create key to fetch user from datastore
    user_key = client.key(USERS, id)
    # retrieves use data using the key
    user = client.get(key=user_key)
    if sub == user['sub']:
        return True
    else:
        return False

@app.route('/' + USERS + '/<int:id>' + '/avatar', methods=['POST'])
def update_avatar(id):
    try:
        payload = verify_jwt(request)
    except:
        return ({'Error': 'Unauthorized'}, 401)
    
    # checking if logged in user with sub in jwt is same user
    # whose id is in the url
    if is_the_user(payload['sub'], id) == False:
        return ({'Error': 'You don\'t have permission on this resource'}, 403)

    # check if request includes a file and retrieves it
    if 'file' not in request.files:
        return ({'Error': 'The request body is invalid'}, 400)
    
    file_obj = request.files['file']
    storage_client = storage.Client()
    # retrieve bucket where avatars are
    bucket = storage_client.get_bucket(BUCKET)
    # list all blobs in the bucket files
    blobs = list_my_blobs(BUCKET)
    
    for blob in blobs:
        if blob is None or not hasattr(blob, 'metadata'):
            continue
        if blob.metadata is None or not 'id' in blob.metadata:
            continue

        if blob.metadata['id'] == str(id):
            blob.delete()
    # create new blob file obj in the bucket 
    blobs = bucket.blob(file_obj.filename)
    # meta of blob set with id of user so file is associated with them
    blobs.metadata = {'id': str(id)}
    # ensures file ptr is at beginning of file
    file_obj.seek(0)
    # uploads form file_obj bucket
    blobs.upload_from_file(file_obj)

    # setting up the new data store avatar
    # key to avatar datastore kind
    avatar_key = client.key(AVATARS)

    avatar_query = client.query(kind=AVATARS)
    # filters the avatars by student_id to find users avatar
    avatar_query.add_filter('student_id', '=', id)
    #results = avatar_query.fetch()
    results = list(avatar_query.fetch())

    #res = {}

    #if results is None:
    if len(results) == 0:
        # proceed to update this with the info 
        # create new entity of kind avatars
        new_avatar = datastore.entity.Entity(key=client.key(AVATARS))

        new_avatar.update({
            'student_id': id,
            # updates our avatar datastore with student1.png
            'file_name': file_obj.filename
        })
        client.put(new_avatar)
    
    else:
        # user already has avatar in datastore
        results[0]['file_name'] = file_obj.filename

    res = {}
    res['avatar_url'] = URL + '/' + USERS + '/' + str(id) + '/avatar'
    return res, 200

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -   
#                       #5: GET A USERS AVATAR               
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
@app.route('/images/<file_name>', methods=['GET'])
def get_image(file_name):
    storage_client = storage.Client()
    bucket = storage_client.get_bucket(BUCKET)

    # Create a blob with the given file name
    blob = bucket.blob(file_name)

    # Create a file object in memory using Python io package
    file_obj = io.BytesIO()

    # Download the file from Cloud Storage to the file_obj variable
    blob.download_to_file(file_obj)

    # Position the file_obj to its beginning
    file_obj.seek(0)

    # Send the object as a file in the response with the correct MIME type and file name
    return send_file(file_obj, mimetype='image/x-png', download_name=file_name)

@app.route('/' + USERS + '/<int:user_id>' + '/avatar', methods=['GET'])
def get_user_avatar(user_id):
    try:
        payload = verify_jwt(request) # Verify the JWT
    except:
        return {'Error': 'Unauthorized'}, 401

    user_key = client.key(USERS, user_id)
    user = client.get(key=user_key)

    if user is None:
        #
        # JWT is vaild, but user not found, so *technically*
        # the JWT does not belogn to this user. Return 403.
        #
        return { "Error": "You don't have permission on this resource" }, 403


    if user['sub'] != payload['sub']:
        return { "Error": "You don't have permission on this resource" }, 403

    avatar_query = client.query(kind=AVATARS)
    avatar_query.add_filter('student_id', '=', user.key.id)
    avatar_results = list(avatar_query.fetch())

    if len(avatar_results) != 0:
        #
        # User has avatar in the datastore.
        try:
        #
            return get_image(avatar_results[0]['file_name'])
        ############
        except:
            pass
        finally:
            client.delete(client.key(AVATARS, user.key.id))

    return { "Error": "Not found"}, 404


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -   
#                       #6: DELETE USERS AVATAR               
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
@app.route('/images/<file_name>', methods=['DELETE'])
def delete_image(file_name):
    storage_client = storage.Client()
    bucket = storage_client.get_bucket(BUCKET)
    blob = bucket.blob(file_name)
        
    # Delete the file from Cloud Storage
    blob.delete()
    return '',204

@app.route('/' + USERS + '/<int:user_id>' + '/avatar', methods=['DELETE'])
def delete_avatar(user_id):
    try:
        payload = verify_jwt(request) # Verify the JWT
    except:
        return {'Error': 'Unauthorized'}, 401

    user_key = client.key(USERS, user_id)
    user = client.get(key=user_key)

    if user is None:
        return { "Error": "User does not exist" }, 403

    if user['sub'] != payload['sub']:
        return { "Error": "You don't have permission on this resource" }, 403

    avatar_query = client.query(kind=AVATARS)
    avatar_query.add_filter('student_id', '=', user.key.id)
    avatar_results = list(avatar_query.fetch())

    if len(avatar_results) != 0:
        #
        # User has avatar in the datastore.
        #
        try:
            # if delete raises exception, otherwise ignore
            #client.delete(client.key(AVATARS, use.key.id))
            #return get_image(avatar_results[0]['file_name'])
            return delete_image(avatar_results[0]['file_name'])
        except:
            pass
        finally:
            client.delete(client.key(AVATARS, user.key.id))

    return { "Error": "Not found"}, 404


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -   
#                       #7: CREATE A COURSE                          |
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
@app.route('/' + COURSES, methods=['POST'])
def new_course():
    content = request.get_json()
    # create new entity for courses kind.
    # entity is initialized with key that refers to courses kind.
    new = datastore.entity.Entity(key=client.key(COURSES))

    try:
        payload = verify_jwt(request)
    except:
        return ({'Error': 'Unauthorized'}, 401)
    
    for i in range(len(fields_required)):
        if fields_required[i] not in content:
            return ({'Error': 'The request body is invalid'}, 400)
    
    # queries users kind in datastore to check if user has role in admin
    ad_query = client.query(kind=USERS)
    # match users sub value in the jwt payload
    # and role being admin
    ad_query.add_filter('sub', '=', payload['sub'])
    ad_query.add_filter('role', '=', 'admin')
    # results will contain list of users ith this role
    # if results is empty it means user is not an admin course
    # creation wont be allowed
    results = list(ad_query.fetch())
    
    # get user with instructor id specific in content['instrcutor_id']
    user_key = client.key(USERS, content['instructor_id'])
    user = client.get(key=user_key)

    if not results:
        return ({'Error': 'You don\'t have permission on this resource'}, 403)
    
    if user['role'] != 'instructor':
        return ({'Error': 'The request body is invalid'}, 400)
    
    # populate newly created course entity 
    new.update({
        "subject": content["subject"],
        "number": content["number"],
        "title": content["title"],
        "term": content["term"],
        "instructor_id": content["instructor_id"],
        "enrollment": []
    })

    # store new course entity
    client.put(new)
    # need to delete enrollment field from course entity before running
    del new['enrollment']
    new['id'] = new.key.id
    #api_url = URL + DOMAIN + '/' + COURSES + '/' + str(new.key.id)
    api_url = URL + '/' + COURSES + '/' + str(new.key.id)
    new['self'] = api_url
    return (new, 201)

# resource citation: for pagination
# website: stackoverflow
# title: flask pagination displaying too many results
# url:https://stackoverflow.com/questions/43679593/flask-paginate-displaying-too-many-results


# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -   
#                       #8: GET ALL COURSES                         |
#  list of courses returned using pagination, with correct data and |
#  and sort the order.                                              |               
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
@app.route('/' + COURSES, methods=['GET'])
def get_allcourse():
    args = request.args

    # we only want 3 courses at a time to be displayed
    limit = 3
    offset = 0
    
    course_query = client.query(kind=COURSES)
    course_query.order = ['subject']
    # set limit of a single page to 3 entries
    i = course_query.fetch(limit=limit, offset=offset)
    a_page = i.pages
    # casts as a list
    results = list(next(a_page))

    # iterate over the results lists to remove any enrollment properties
    # we won't want to be displaying that for this
    for course in results:
        if 'enrollment' in course:
            del course['enrollment']
        course['id'] = str(course.key.id)
        link = URL + '/' + COURSES + '/' + str(course.key.id)
        course['self'] = link
    # gets the beginning of the next page
    # url_next = URL + '/' + COURSES + "?limit=3" + "&offset=0"
    url_next = URL + '/' + COURSES + "?limit=3&offset=3"
    ###return('courses: results, 'next':url_next)
    return ({'courses': results, 'next':url_next})

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -   
#                       #9: GET A COURSE                            |               
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
@app.route('/' + COURSES + '/<int:id>', methods=['GET'])
def get_course(id):
    course_key = client.key(COURSES, id)
    course = client.get(key=course_key)

    if not course:
        return ({'Error': 'Not found'}, 404)
    
    # we don't need to display enrollment so deleting this property
    del course['enrollment']
    course['id'] = str(course.key.id)
    api_url = URL + '/' + COURSES + '/' + str(course.key.id)
    # the self url from last assignment didn't work so this
    # doesn't need the extra / for some reason
    course['self'] = api_url
    return course

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -   
#                       #10: UPDATE A COURSE                        |
#                  performs partial update on course                |               
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
#
# Param {id} : the course ID
#
@app.route('/' + COURSES + '/' + '<int:course_id>', methods=['PATCH'])
def update_course(course_id):
    content = request.get_json()

    # if request is empty then do nothing
    if not content:
        # The request is a JSON object with no properties.
        # The rubric says this is valid, but nothing gets updated
        return ({'Success': 'request body empty'}, 200)

    # The request is missing the `instructor_id` key/attr.
    if not 'instructor_id' in content:
        return { "Error": "The request body is invalid" }, 400

    try:
        # verify the jwt
        payload = verify_jwt(request)

    except:
        return {'Error': 'Unauthorized'}, 401

    # Get user key & retrieve this user from the USERS datastore, if it exists.
    user_key = client.key(USERS, content['instructor_id'])
    user = client.get(key=user_key) 
    
    # gets only 1 course 
    # use course key and if not found error check proceeds
    course_key = client.key(COURSES, course_id)
    course = client.get(key=course_key)
    
    ############## Error checking. ########################
    # No matching user found.
    if user is None:
        return { "Error": "The request body is invalid" }, 400
    
    # User is not an admin.
    if user['role'] != 'admin':
        return { "Error": "You don't have permission on this resource" }, 403
    
    # No matching course found.
    if course is None:
        return { "Error": "You don't have permission on this resource" }, 403
    ########################################################
    
    # else course found and we write values request body sent into 
    # this entity and push the updates to the datastore
    if 'subject' in content: course['subject'] = content['subject']
    if 'number' in content: course['number'] = content['number']
    if 'title' in content: course['title'] = content['title']
    if 'term' in content: course['term'] = content['term']
    if 'instructor_id' in content: course['instructor_id'] = content['instructor_id']
    
    # push ^ to update
    client.put(course)
    
    return {
        'id' : course.id, # this might need to be `course_id`, not `course.id` ...?
        'self' : f'{URL}/{COURSES}/{course.id}',
        'instructor_id' : course['instructor_id'],
        'number' : course['number'],
        'subject' : course['subject'],
        'term' : course['term'],
        'title' : course['title']
    }, 200

    #return ({ "Success": "Course successfully updated." }, 200 )
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -   
#                       #11: DELETE A COURSE                         |
# deletes enrollment of all students that were enrolled in the course|
# instructor teaching the course is no longer associated with course.|               
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
@app.route('/' + COURSES + '/' + '<int:course_id>', methods=['DELETE'])
def delete_course(course_id):
    try:
        # verify the jwt
        payload = verify_jwt(request)

    except:
        return { 'Error': 'Unauthorized' }, 401

    # gets key for courses kind
    course_key  = client.key(COURSES, course_id)
    #user_key = client.key(USERS)                    # Get the key for the USERS kind.
    #user_key = client.key(USERS, payload['sub'])                    # Get the key for the USERS kind.
    
    # get course from datastore if it exists
    course = client.get(key=course_key)
    #user = client.get(key=user_key)                 # Get the current user from datastore (if it exists).
    
    user_query = client.query(kind=USERS)
    user_query.add_filter('sub', '=', payload['sub'])
    user_query.add_filter('role', '=', 'admin')

    try:
        user = list(user_query.fetch(limit=1))[0]
    except:
        # set user to none if there is nothing to return otherwise 
        # [0] will be out of bounds
        user = None

    ######################## ERROR CHECKING ########################
    # the user does not exist.
    if user is None:
        return { "Error": "The request body is invalid" }, 400

    # The course does not exist.
    #
    #if course is None:
    #    return { "Error": "The JWT is valid, but the course does not exist." }, 403

    # user is not an adim.
    if user['role'] != 'admin':
        return { "Error": "You don't have permission on this resource" }, 403

    # course does not exist.
    if course is None:
        return { "Error": "You don't have permission on this resource" }, 403

    ######################

    # delete the course from the datastore (by using the course's datastore key).
    client.delete(course_key)

    ## return success??
    #return ({},204)
    return ('',204)

    # it whines about internal server error when you do this
    #return 204
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -   
#                       #12: UPDATE ENROLLMENT IN COURSE            | 
#                 enroll or disenroll students from a course        |      
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
@app.route('/' + COURSES + '/' + '<int:course_id>' + '/students', methods=['PATCH'])
def update_enrollment(course_id):
    content = request.get_json()
    try:
        payload = verify_jwt(request) # Verify the JWT
    except:
        return { 'Error': 'Unauthorized' }, 401

    course_key = client.key(COURSES, course_id) 
    course = client.get(key=course_key)         
    user_query = client.query(kind=USERS)
    #user_query.add_filter('role', 'IN', [ 'admin', 'instructor' ])  
    user_query.add_filter('sub', '=', payload['sub'])              
    #user = user_query.fetch(limit=1)
    #user = list(user_query.fetch(limit=1))
    user = list(user_query.fetch())

    combined_id_list = content['add'] + content['remove']

    if course is None:
        return { "Error": "You don't have permission on this resource" }, 403

    if not user:
    #if user is None:
        return {
            "Error": "You don't have permission on this resource"
            }, 403

# *** * * * ** * * ** *
    user = user[0]
    # for i in user:
    # if role == instructor
    # if course[instructor_id] != i.key.id:
    # 403 you're not instructor for the course

    if user['role'] != 'admin' and user['role'] != 'instructor':
        return {
            "Error": "You don't have permission on this resource"
            }, 403
# ************


    # Make sure that "there is no common value between the arrays 'add' and 'remove'".
    #
    if [ i for i in combined_id_list if i in content['add'] and i in content['remove'] ]:
        return { "Error": "Enrollment data is invalid" }, 409

    students_to_enroll = [] # A list of students to enroll in the course (from content['add']).
    students_to_remove = [] # A list of students to remove from the course (from content['add']).

    for student_id in content['add']:
        result = client.get( key=client.key(USERS, student_id) )
        if result is None or result['role'] != 'student':
            return { "Error": "Enrollment data is invalid" }, 409
        elif not student_id in course['enrollment']:
            students_to_enroll.append(student_id)

    for student_id in content['remove']:
        result = client.get( key=client.key(USERS, student_id) )
        if result is None or result['role'] != 'student':
            return { "Error": "Enrollment data is invalid" }, 409
        elif student_id in course['enrollment']:
            students_to_remove.append(student_id)
    
    course['enrollment'] = \
            list( set( course['enrollment'] + students_to_enroll ) - set(students_to_remove) )
    
    client.put(course)
    #return {}, 200
    return {
        'id' : course.id, # this might need to be `course_id`, not `course.id` ...?
        'self' : f'{URL}/{COURSES}/{course.id}',
        'instructor_id' : course['instructor_id'],
        'number' : course['number'],
        'subject' : course['subject'],
        'term' : course['term'],
        'title' : course['title']
    }, 200

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -   
#                       #13: GET ENROLLMENT IN A COURSE             |                                         
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
@app.route('/' + COURSES + '/<int:course_id>' + '/students', methods=['GET'])
def get_course_enrollment(course_id):
    try:
        payload = verify_jwt(request)
    except:
        return { 'Error': 'Unauthorized' }, 401

    course_key = client.key(COURSES, course_id)
    course = client.get(key=course_key)

    if course is None:
        return { "Error": "You don't have permission on this resource" }, 403

    user_key = client.query(kind=USERS)
    user_key.add_filter('sub', '=', payload['sub'])
    results = list(user_key.fetch())
    user = results[0]
    #user_key = client.key(USERS, course['instructor_id'])
    #user = client.get(key=user_key)
    #
    ### Check if JWT does not belong to admin or
    ### instructor of this course.
    if results is None:
        return {"Error": "You don't have permission on this resource"}, 403
    
    # case where jwt is an admin and thus can update
    if user['role'] == 'admin':
        return course['enrollment'], 200
    
    # case where instructor jwt, but is not the instructor
    # that is teaching that particular course, therefore doesnt
    # have the correct permissions to edit
    if user['role'] == 'instructor':
        if user.key.id != course['instructor_id']:
            return {"Error": "You don't have permission on this resource"}, 403

        return ( course['enrollment'], 200 )
    
    return {"Error": "You don't have permission on this resource"}, 403


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)

