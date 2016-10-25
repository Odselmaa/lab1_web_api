from flask import Flask, render_template, request, redirect, jsonify, url_for, flash
from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, User
from flask import session as login_session
import random
import string
import sqlite3
# IMPORTS FOR THIS STEP
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests
from oauth2client.client import AccessTokenCredentials

app = Flask(__name__)

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
CLIENT_SECRET = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_secret']
REDIRECT_URI = json.loads(
    open('client_secrets.json', 'r').read())['web']['redirect_uris']

APPLICATION_NAME = "Restaurant Menu Application"

CLIENT_ID_VK = 5671773
CLIENT_SECRET_VK = "KkWUkzMQXuRNSHWepyMH"

# Connect to Database and create database session
engine = create_engine('sqlite:///users.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


@app.route("/")
@app.route('/index')
def get_index_page():
    href = None
    if login_session.get('username') is None:
        return redirect('/loginpage')

    if login_session.get('picture') is None:
        login_session['picture'] = 'static/user.png'

    return render_template(
        "main.html",
        USERNAME=login_session.get("username"),
        PHOTO_URL=login_session.get('picture'))


@app.route('/loginpage')
def showLogin():
    if login_session.get('username') is not None:
        return redirect('/index')

    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in range(32))
    login_session['state'] = state
    # return "The current session state is %s" % login_session['state']
    return render_template('login.html', STATE=state)

@app.route('/logout',  methods=['POST', 'GET'])
def logout():
    service_provider = login_session.get('service_provider')
    if service_provider == 'google':
        return redirect('/gdisconnect')
    elif service_provider == 'vk':
        return redirect('/vk_disconnect')
    elif service_provider == 'github':
        return redirect('/github_disconnect')
    else:
        return redirect('/signout')


@app.route('/signup', methods=['POST'])
def sign_up():
    username = request.values.get('username')
    password = request.values.get('password')

    if username and password:
        user = User(username=username)
        user.hash_password(password)
        session.add(user)
        try:
            session.commit()
            user = session.query(User).filter_by(username=username).one()
        except:
            response = make_response("Username is not available", 400)
            response.headers['Content-Type'] = 'application/json'
            return response
        else:
            token = user.generate_auth_token().decode('ascii')
            response = make_response("Successfully registered! %s" % username, 201)
            response.set_cookie('token', token)
            return jsonify({'username': user.username, 'token': token}), 201
    else:
        return jsonify("Username or password is None"), 400

@app.route('/signin', methods=['POST'])
def sign_in():

    username = request.values.get('username')
    password = request.values.get('password')

    if not username or not password:
        return jsonify(data="Username or password is empty!", status=400)

    user = session.query(User).filter_by(username=username).first()
    if not user:
        return jsonify(data="User is not found!", status=404)

    if not user.verify_password(password):
        return jsonify(data ="Username or password is not correct!", status=400)

    login_session['username'] = user.username
    return redirect("/index")

@app.route('/signout')
def signout():
    if not login_session.get('username'):
        return jsonify(data="Current user didn't sign in", status= 400)

    del login_session['username']
    return jsonify(data = "Successfully signed out", status=200)

@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    login_session['service_provider'] = 'google'

    output = ''
    output += login_session['username'] + "\n"
    output += login_session['picture'] + "\n"
    output += login_session['gplus_id'] + "\n"



    flash("you are now logged in as %s" % login_session['username'])
    print "done! " + output

    return output

    # DISCONNECT - Revoke a current user's token and reset their login_session


@app.route('/gdisconnect', methods=['POST', 'GET'])
def gdisconnect():
    access_token = login_session.get('access_token')
    print 'In gdisconnect access token is %s', access_token
    print 'User name is: '
    print login_session.get('username')

    if access_token is None:
        print 'Access Token is None'
        response = make_response('Current user not connected.', 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    print 'result is '
    print result

    if result['status'] == '200':
        del login_session['service_provider']
        del login_session['access_token']
        #del login_session['credentials']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        print result
        response = make_response(json.dumps('Failed to revoke token for given user.'), 400)
        response.headers['Content-Type'] = 'application/json'
        return response


@app.route("/vkconnect")
def vkconnect():
    url = "https://oauth.vk.com/authorize?client_id=5671773" + \
          "&display=page&redirect_uri=" + \
          "http://localhost:5000/vkprocess&scope=offline&response_type=code&v=5.52"
    #  url = 'https://oauth.vk.com/access_token?client_id=%d&client_secret=%s&v=5.1&grant_type=client_credentials'\
    # %(CLIENT_ID_VK,CLIENT_SECRET_VK)
    return redirect(url)


@app.route("/vkprocess", methods=['GET'])
def vkprocess():
    code = request.args.get('code')
    if code is not None:
        url = "https://oauth.vk.com/access_token?client_id=" + str(CLIENT_ID_VK) + \
              "&client_secret=" + CLIENT_SECRET_VK + \
              "&code=" + code + "&redirect_uri=http://localhost:5000/vkprocess"

        h = httplib2.Http()
        result = h.request(url, 'GET')
        header = result[0]
        body = json.loads(result[1])

        print(body)

        if header['status'] == "401":
            response = make_response(body['error_description'], 401)
            response.headers['Content-Type'] = 'application/json'
            return response

        if header["status"] == "200":
            response = make_response(body["access_token"], 200)
            response.headers['Content-Type'] = 'application/json'

            login_session['state'] = body["access_token"]
            login_session['vk_user_id'] = body["user_id"]
            print(type(body["user_id"]))

            url = "https://api.vk.com/method/users.get?user_ids=" + str(body["user_id"]) + \
                  "&fields=photo_100&name_case=nom&" \
                  "access_token=" + str(body["access_token"])

            h = httplib2.Http()
            result = h.request(url, 'GET')
            body = json.loads(result[1])

            login_session['username'] = body['response'][0].get('first_name')
            login_session['picture'] = body['response'][0].get('photo_100')
            login_session['service_provider'] = 'vk'
            return redirect('/index')

    else:
        response = make_response("Code not defined", 401)
        response.headers['Content-Type'] = 'application/json'
        return response


@app.route("/vk_disconnect", methods=['POST', 'GET'])
def vk_disconnect():
    if login_session.get('vk_user_id'):
        login_session.clear()
        response = make_response("Successfully disconnected", 200)
        response.headers['Content-Type'] = 'application/json'
        return response
        # return render_template('/redirect.html', MESSAGE='Successfully disconnected')
    else:
        response = make_response("Current user didn't connected", 401)
        response.headers['Content-Type'] = 'application/json'
        return response


def return_response(msg, code):
    response = make_response(json.dumps(msg), code)
    return response


if __name__ == '__main__':
    app.secret_key = "12222"
    app.run(host='127.0.0.1', port=5000, use_reloader=False)

##
#  url = 'https://oauth.vk.com/access_token?client_id={0}&' \
#       'client_secret={CLIENT_SECRET}&v=5.1&grant_type=client_credentials'\
# .format(CLIENT_ID_VK,CLIENT_SECRET=CLIENT_SECRET_VK)
# #
