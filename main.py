# Name: Derek Greene
# OSU Email: greenede@oregonstate.edu
# Course: CS493 - Cloud Application Development
# Assignment: Portfolio Project - Tarpaulin Course Management Tool
# Due Date: 6/6/2025
# Description: Developed a RESTful API for an application called Tarpaulin,
#              a lightweight course management tool that's an "alternative" to Canvas.
#              This application is deployed on Google Cloud Platform using Google App
#              Engine and Datastore. Auth0 is used for authentication.

import requests, json, os, tempfile
from flask import Flask, request, jsonify, url_for, send_file
from google.cloud import datastore
from google.cloud import storage
from six.moves.urllib.request import urlopen
from jose import jwt
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv, find_dotenv

app = Flask(__name__)
load_dotenv(find_dotenv())

DOMAIN = os.getenv('DOMAIN')
CLIENT_ID = os.getenv('CLIENT_ID')
CLIENT_SECRET = os.getenv('CLIENT_SECRET')
GCP_BUCKET = os.getenv('GCP_BUCKET')
ALGORITHMS = ["RS256"]
ERROR_400 = {"Error": "The request body is invalid"}
ERROR_401 = {"Error": "Unauthorized"}
ERROR_403 = {"Error": "You don't have permission on this resource"}
ERROR_404 = {"Error": "Not found"}
ERROR_409 = {"Error": "Enrollment data is invalid"}

app.secret_key = os.getenv('SECRET_KEY')
client = datastore.Client(project='final-462001')
storage = storage.Client()
bucket = storage.bucket(GCP_BUCKET)
oauth = OAuth(app)

auth0 = oauth.register(
    'auth0',
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    api_base_url="https://" + DOMAIN,
    access_token_url="https://" + DOMAIN + "/oauth/token",
    authorize_url="https://" + DOMAIN + "/authorize",
    client_kwargs={'scope': 'openid profile email'},
)

# This method is adapted from https://auth0.com/docs/quickstart/backend/python/01-authorization?_ga=2.46956069.349333901.1589042886-466012638.1589042885#create-the-jwt-validation-decorator
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
        raise AuthError({"code": "no auth header", "description": "Authorization header is missing"}, 401)

    jsonurl = urlopen("https://"+ DOMAIN+"/.well-known/jwks.json")
    jwks = json.loads(jsonurl.read())
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.JWTError:
        raise AuthError({"code": "invalid_header", "description": "Invalid header. " "Use an RS256 signed JWT Access Token"}, 401)

    if unverified_header["alg"] == "HS256":
        raise AuthError({"code": "invalid_header", "description": "Invalid header. " "Use an RS256 signed JWT Access Token"}, 401)

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
                issuer="https://"+ DOMAIN+"/")

        except jwt.ExpiredSignatureError:
            raise AuthError({"code": "token_expired", "description": "token is expired"}, 401)
        except jwt.JWTClaimsError:
            raise AuthError({"code": "invalid_claims", "description": "incorrect claims," " please check the audience and issuer"}, 401)
        except Exception:
            raise AuthError({"code": "invalid_header", "description": "Unable to parse authentication" " token."}, 401)
        return payload
    else:
        raise AuthError({"code": "no_rsa_key", "description": "No RSA key in JWKS"}, 401)

@app.route('/decode', methods=['GET'])
def decode_jwt():
    payload = verify_jwt(request)
    return payload


@app.route('/users/login', methods=['POST'])
def login_user():
    content = request.get_json()

    if not content or 'username' not in content or 'password' not in content:
        return jsonify(ERROR_400), 400

    username = content["username"]
    password = content["password"]
    body = {'grant_type':'password',
            'username':username,
            'password':password,
            'client_id':CLIENT_ID,
            'client_secret':CLIENT_SECRET}

    headers = {'content-type': 'application/json'}
    url = 'https://' + DOMAIN + '/oauth/token'
    r = requests.post(url, json=body, headers=headers)

    try:
        data = r.json()
    except ValueError:
        return jsonify(ERROR_401), 401
    if "error" in data:
        return jsonify(ERROR_401), 401

    if r.status_code == 401:
        return jsonify({"Error": "Username or password is incorrect"}), 401
    else:
        token = r.json().get('id_token')
        return jsonify({"token": token}), 200

@app.route('/users', methods=['GET'])
def get_all_users():
    try:
        payload = verify_jwt(request)
    except AuthError as err:
        if err.status_code == 401:
            return jsonify(ERROR_401), 401
        elif err.status_code == 403:
            return jsonify(ERROR_403), 403
        else:
            return jsonify(ERROR_401), 401

    user_sub = payload['sub']
    query = client.query(kind='users')
    query.add_filter('sub', '=', user_sub)
    results = list(query.fetch())

    if not results:
        return jsonify(ERROR_403), 403

    current_user = results[0]
    if current_user.get('role') != 'admin':
        return jsonify(ERROR_403), 403

    query = client.query(kind='users')
    users = list(query.fetch())
    response = []
    for user in users:
        response.append({
            "id": user.key.id,
            "role": user.get('role'),
            "sub": user.get('sub')
        })
    return jsonify(response), 200


@app.route('/users/<int:user_id>', methods=['GET'])
def get_user(user_id):
    try:
        payload = verify_jwt(request)
    except AuthError as err:
        if err.status_code == 401:
            return jsonify(ERROR_401), 401
        elif err.status_code == 403:
            return jsonify(ERROR_403), 403
        else:
            return jsonify(ERROR_401), 401

    requester_sub = payload['sub']
    query = client.query(kind='users')
    query.add_filter('sub', '=', requester_sub)
    requester_results = list(query.fetch())

    if not requester_results:
        return jsonify(ERROR_403), 403

    requester = requester_results[0]
    requester_role = requester.get('role')
    user_key = client.key('users', user_id)
    user = client.get(user_key)

    if not user:
        return jsonify(ERROR_404), 404

    if requester_role != 'admin' and requester_sub != user.get('sub'):
        return jsonify(ERROR_403), 403

    response = {
        "id": user.key.id,
        "role": user.get('role'),
        "sub": user.get('sub')
    }

    if 'avatar' in user:
        response["avatar_url"] = url_for('user_avatar', user_id=user.key.id, _external=True)

    if user.get('role') in ['instructor', 'student']:
        course_links = []
        if 'courses' in user:
            for course_id in user['courses']:
                course_links.append(url_for('get_course_by_id', course_id=course_id, _external=True))
        response["courses"] = course_links

    return jsonify(response), 200


@app.route('/users/<int:user_id>/avatar', methods=['GET', 'POST', 'DELETE'])
def user_avatar(user_id):
    if request.method == 'POST':
        if 'file' not in request.files:
            return jsonify(ERROR_400), 400

        try:
            payload = verify_jwt(request)
        except AuthError:
            return jsonify(ERROR_401), 401

        user_key = client.key('users', user_id)
        user = client.get(user_key)
        if not user:
            return jsonify(ERROR_403), 403

        jwt_sub = payload.get('sub', '').strip()
        user_sub = user.get('sub', '').strip()

        q = client.query(kind='users')
        q.add_filter('sub', '=', jwt_sub)
        requester = list(q.fetch())
        is_admin = requester and requester[0].get('role') == 'admin'

        print(f"user_sub: {user_sub}, jwt_sub: {jwt_sub}, is_admin: {is_admin}")

        if user_sub != jwt_sub:
            return jsonify(ERROR_403), 403

        file = request.files['file']
        blob = bucket.blob(f"avatars/{user_id}.png")
        blob.upload_from_file(file, content_type='image/png')

        user['avatar'] = f"avatars/{user_id}.png"
        client.put(user)

        return jsonify({
            "avatar_url": url_for('user_avatar', user_id=user_id, _external=True)
        }), 200

    elif request.method == 'GET':
        try:
            payload = verify_jwt(request)
        except AuthError:
            return jsonify(ERROR_401), 401

        user_key = client.key('users', user_id)
        user = client.get(user_key)
        if not user:
            return jsonify(ERROR_404), 404

        jwt_sub = payload.get('sub', '').strip()
        user_sub = user.get('sub', '').strip()

        if user_sub != jwt_sub:
            return jsonify(ERROR_403), 403

        blob = bucket.blob(f"avatars/{user_id}.png")
        if not blob.exists():
            return jsonify(ERROR_404), 404

        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            blob.download_to_filename(temp_file.name)
            return send_file(temp_file.name, mimetype='image/png')

    elif request.method == 'DELETE':
        try:
            payload = verify_jwt(request)
        except AuthError:
            return jsonify(ERROR_401), 401

        user_key = client.key('users', user_id)
        user = client.get(user_key)
        if not user:
            return jsonify(ERROR_403), 403

        jwt_sub = payload.get('sub', '').strip()
        user_sub = user.get('sub', '').strip()

        if jwt_sub != user_sub:
            return jsonify(ERROR_403), 403

        blob = bucket.blob(f"avatars/{user_id}.png")
        if not blob.exists():
            return jsonify(ERROR_404), 404

        blob.delete()

        if 'avatar' in user:
            del user['avatar']
            client.put(user)

        return '', 204


@app.route('/courses', methods=['GET', 'POST'])
def courses():
    if request.method == 'POST':
        try:
            payload = verify_jwt(request)
        except AuthError:
            return jsonify(ERROR_401), 401

        jwt_sub = payload.get('sub')
        q = client.query(kind='users')
        q.add_filter('sub', '=', jwt_sub)
        requester = list(q.fetch())
        if not requester or requester[0].get('role') != 'admin':
            return jsonify(ERROR_403), 403

        data = request.get_json()
        required_fields = ['subject', 'number', 'title', 'term', 'instructor_id']
        if not data or any(field not in data for field in required_fields):
            return jsonify(ERROR_400), 400

        instructor_key = client.key('users', data['instructor_id'])
        instructor = client.get(instructor_key)
        if not instructor or instructor.get('role') != 'instructor':
            return jsonify(ERROR_400), 400

        course_key = client.key('courses')
        course = datastore.Entity(key=course_key)
        course.update({
            'subject': data['subject'],
            'number': data['number'],
            'title': data['title'],
            'term': data['term'],
            'instructor_id': data['instructor_id']
        })
        client.put(course)

        course_id = course.key.id
        response_body = {
            'id': course_id,
            'subject': data['subject'],
            'number': data['number'],
            'title': data['title'],
            'term': data['term'],
            'instructor_id': data['instructor_id'],
            'self': url_for('get_course_by_id', course_id=course_id, _external=True)
        }
        return jsonify(response_body), 201

    elif request.method == 'GET':
        try:
            offset = int(request.args.get('offset', 0))
            limit = int(request.args.get('limit', 3))
        except ValueError:
            return jsonify(ERROR_400), 400

        query = client.query(kind='courses')
        query.order = ['subject']
        results = list(query.fetch())

        paged_courses = results[offset:offset + limit]
        course_list = []
        for course in paged_courses:
            course_list.append({
                'id': course.key.id,
                'subject': course['subject'],
                'number': course['number'],
                'title': course['title'],
                'term': course['term'],
                'instructor_id': course['instructor_id'],
                'self': url_for('get_course_by_id', course_id=course.key.id, _external=True)
            })

        response_body = {'courses': course_list}

        if offset + limit < len(results):
            response_body['next'] = url_for('courses', offset=offset + limit, limit=limit, _external=True)

        return jsonify(response_body), 200


@app.route('/courses/<int:course_id>', methods=['GET', 'PATCH', 'DELETE'])
def get_course_by_id(course_id):
    if request.method == 'GET':
        course_key = client.key('courses', course_id)
        course = client.get(course_key)
        if not course:
            return jsonify(ERROR_404), 404

        return jsonify({
            'id': course_id,
            'subject': course['subject'],
            'number': course['number'],
            'title': course['title'],
            'term': course['term'],
            'instructor_id': course['instructor_id'],
            'self': url_for('get_course_by_id', course_id=course_id, _external=True)
        }), 200

    elif request.method == 'PATCH':
        try:
            payload = verify_jwt(request)
        except AuthError:
            return jsonify(ERROR_401), 401

        jwt_sub = payload.get('sub')
        q = client.query(kind='users')
        q.add_filter('sub', '=', jwt_sub)
        requester = list(q.fetch())

        if not requester or requester[0].get('role') != 'admin':
            return jsonify(ERROR_403), 403

        course_key = client.key('courses', course_id)
        course = client.get(course_key)
        if not course:
            return jsonify(ERROR_403), 403

        content = request.get_json()
        if content is None:
            return jsonify(ERROR_400), 400

        if 'instructor_id' in content:
            instructor_key = client.key('users', content['instructor_id'])
            instructor = client.get(instructor_key)
            if not instructor or instructor.get('role') != 'instructor':
                return jsonify(ERROR_400), 400
            course['instructor_id'] = content['instructor_id']

        if 'subject' in content:
            course['subject'] = content['subject']
        if 'number' in content:
            course['number'] = content['number']
        if 'title' in content:
            course['title'] = content['title']
        if 'term' in content:
            course['term'] = content['term']

        client.put(course)
        return jsonify({
            'id': course_id,
            'subject': course['subject'],
            'number': course['number'],
            'title': course['title'],
            'term': course['term'],
            'instructor_id': course['instructor_id'],
            'self': url_for('course_students', course_id=course_id, _external=True)
        }), 200

    elif request.method == 'DELETE':
        try:
            payload = verify_jwt(request)
        except AuthError:
            return jsonify(ERROR_401), 401

        jwt_sub = payload.get('sub')
        q = client.query(kind='users')
        q.add_filter('sub', '=', jwt_sub)
        requester = list(q.fetch())

        if not requester:
            return jsonify(ERROR_403), 403
        if requester[0].get('role') != 'admin':
            return jsonify(ERROR_403), 403

        course_key = client.key('courses', course_id)
        course = client.get(course_key)

        if not course:
            return jsonify(ERROR_403), 403

        enrollment_query = client.query(kind='enrollments')
        enrollment_query.add_filter('course_id', '=', course_id)
        enrollments = list(enrollment_query.fetch())
        for enrollment in enrollments:
            client.delete(enrollment.key)

        client.delete(course_key)
        return '', 204


@app.route('/courses/<int:course_id>/students', methods=['GET', 'PATCH'])
def course_students(course_id):
    if request.method == 'GET':
        try:
            payload = verify_jwt(request)
        except AuthError:
            return jsonify(ERROR_401), 401

        jwt_sub = payload.get('sub')

        q = client.query(kind='users')
        q.add_filter('sub', '=', jwt_sub)
        requester_list = list(q.fetch())
        if not requester_list:
            return jsonify(ERROR_403), 403
        requester = requester_list[0]

        course_key = client.key('courses', course_id)
        course = client.get(course_key)
        if not course:
            return jsonify(ERROR_403), 403

        if requester.get('role') != 'admin' and jwt_sub != course.get('instructor_id'):
            return jsonify(ERROR_403), 403

        enrollment_query = client.query(kind='enrollments')
        enrollment_query.add_filter('course_id', '=', course_id)
        enrollments = list(enrollment_query.fetch())

        student_ids = [enrollment['student_id'] for enrollment in enrollments]

        return jsonify(student_ids), 200

    elif request.method == 'PATCH':
        try:
            payload = verify_jwt(request)
        except AuthError:
            return jsonify(ERROR_401), 401

        jwt_sub = payload.get('sub')

        course_key = client.key('courses', course_id)
        course = client.get(course_key)
        if not course:
            return jsonify(ERROR_403), 403

        q = client.query(kind='users')
        q.add_filter('sub', '=', jwt_sub)
        requester = list(q.fetch())
        if not requester:
            return jsonify(ERROR_403), 403

        requester = requester[0]
        requester_role = requester.get('role')

        if requester_role != 'admin' and jwt_sub != course.get('instructor_id'):
            return jsonify(ERROR_403), 403

        content = request.get_json()
        if content is None:
            return jsonify(ERROR_400), 400

        add_ids = content.get('add', [])
        remove_ids = content.get('remove', [])

        if set(add_ids) & set(remove_ids):
            return jsonify(ERROR_409), 409

        if add_ids:
            q = client.query(kind='users')
            q.add_filter('role', '=', 'student')
            students = list(q.fetch())
            student_ids = {student.key.id for student in students}

            if not set(add_ids).issubset(student_ids):
                return jsonify(ERROR_409), 409

        if remove_ids:
            q = client.query(kind='users')
            q.add_filter('role', '=', 'student')
            students = list(q.fetch())
            student_ids = {student.key.id for student in students}

            if not set(remove_ids).issubset(student_ids):
                return jsonify(ERROR_409), 409

        enrollment_query = client.query(kind='enrollments')
        enrollment_query.add_filter('course_id', '=', course_id)
        enrollments = list(enrollment_query.fetch())
        enrolled_student_ids = {enrollment['student_id'] for enrollment in enrollments}

        for student_id in add_ids:
            if student_id not in enrolled_student_ids:
                enrollment_key = client.key('enrollments')
                enrollment = datastore.Entity(key=enrollment_key)
                enrollment.update({
                    'course_id': course_id,
                    'student_id': student_id
                })
                client.put(enrollment)

        for student_id in remove_ids:
            if student_id in enrolled_student_ids:
                for enrollment in enrollments:
                    if enrollment['student_id'] == student_id:
                        client.delete(enrollment.key)
                        break
        return '', 200


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)
