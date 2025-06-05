# Name: Derek Greene
# OSU Email: greenede@oregonstate.edu
# Course: CS493 - Cloud Application Development
# Assignment: Portfolio Project - Tarpaulin Course Management Tool
# Due Date: 6/6/2025
# Description: Developed a RESTful API for an application called Tarpaulin,
#              a lightweight course management tool that's an "alternative" to Canvas.
#              This application is deployed on Google Cloud Platform using Google App
#              Engine and Datastore. Auth0 is used for authentication.

import requests, json, os
from flask import Flask, request, jsonify, url_for
from google.cloud import datastore
from six.moves.urllib.request import urlopen
from jose import jwt
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv, find_dotenv

app = Flask(__name__)
load_dotenv(find_dotenv())
app.secret_key = os.getenv('SECRET_KEY')
client = datastore.Client(project='final-462001')
oauth = OAuth(app)

DOMAIN = os.getenv('DOMAIN')
CLIENT_ID = os.getenv('CLIENT_ID')
CLIENT_SECRET = os.getenv('CLIENT_SECRET')
ALGORITHMS = ["RS256"]
ERROR_400 = {"Error": "The request body is invalid"}
ERROR_401 = {"Error": "Unauthorized"}
ERROR_403 = {"Error": "You don't have permission on this resource"}
ERROR_404 = {"Error": "Not found"}

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


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)
