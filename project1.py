from flask import Flask, render_template, request, redirect, jsonify, url_for, flash
from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, User
from flask import session as login_session
# IMPORTS FOR THIS STEP
import json
import requests

app = Flask(__name__)

CLIENT_ID = json.loads(
    open('client_secret1.json', 'r').read())['web']['client_id']
CLIENT_SECRET = json.loads(
    open('client_secret1.json', 'r').read())['web']['client_secret']
REDIRECT_URI = json.loads(
    open('client_secret1.json', 'r').read())['web']['redirect_uris']

APPLICATION_NAME = "Restaurant Menu Application"

CLIENT_ID_VK = 5671773
CLIENT_SECRET_VK = "KkWUkzMQXuRNSHWepyMH"

# Connect to Database and create database session
engine = create_engine('sqlite:///users.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

@app.route('/login')
def index():


  if 'credentials' not in login_session:
    return redirect(url_for('oauth2callback'))
  credentials = json.loads(login_session['credentials'])
  if credentials['expires_in'] <= 0:
    return redirect(url_for('oauth2callback'))
  else:
    req_uri = 'https://www.googleapis.com/oauth2/v1/userinfo?access_token=%s'%credentials['access_token']
    r = requests.get(req_uri)
    info = json.loads(r)

    print(credentials['access_token'])

    return r.text

@app.route('/oauth2callback')
def oauth2callback():
  if 'code' not in request.args:
      auth_uri = ('https://accounts.google.com/o/oauth2/v2/auth?response_type=code'
                  '&client_id=%s&redirect_uri=http://localhost:5000/oauth2callback&scope=profile email openid') \
                 % (CLIENT_ID)
      return redirect(auth_uri)
  else:
    auth_code = request.args.get('code')
    data = {'code': auth_code,
            'client_id': CLIENT_ID,
            'client_secret': CLIENT_SECRET,
            'redirect_uri': REDIRECT_URI,
            'grant_type': 'authorization_code'}
    r = requests.post('https://www.googleapis.com/oauth2/v4/token', data=data)
    login_session['credentials'] = r.text
    print(r.text)
    return redirect(url_for('index'))


if __name__ == '__main__':
    app.secret_key = "12222"
    app.run(host='127.0.0.1', port=5000, use_reloader=False)

##
#  url = 'https://oauth.vk.com/access_token?client_id={0}&' \
#       'client_secret={CLIENT_SECRET}&v=5.1&grant_type=client_credentials'\
# .format(CLIENT_ID_VK,CLIENT_SECRET=CLIENT_SECRET_VK)
# #
