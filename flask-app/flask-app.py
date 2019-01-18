#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (C) 2017  Adel "0x4D31" Karimi

# BEGIN

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

# END

from flask import Flask, request, render_template, send_file, flash, redirect, url_for, session, logging
import logging
import sys
import os
import json
import time
import urllib.request
import urllib.error
import smtplib
import base64
from twilio.rest import Client
from flask_mysqldb import MySQL
from wtforms import Form, StringField, TextAreaField, PasswordField, validators
from passlib.hash import sha256_crypt
from functools import wraps


app = Flask(__name__)

# Config MySQL
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'thomas'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'honeyku'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'

# init MYSQL
mysql = MySQL(app)


__author__ = 'Oliver "othornew" Thornewill \
			  Adel "0x4d31" Karimi'
__version__ = '0.2'

# Log to stdout
# On Heroku, anything written to stdout or stderr is captured into your logs.
# https://devcenter.heroku.com/articles/logging
logger = logging.getLogger(__name__)
out_hdlr = logging.StreamHandler(sys.stdout)
out_hdlr.setFormatter(logging.Formatter('%(asctime)s %(message)s'))
out_hdlr.setLevel(logging.INFO)
logger.addHandler(out_hdlr)
logger.setLevel(logging.INFO)


@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def catch_all(path):
	# Load the config file
	config=load_config()
	# Honeytoken alerts
	if request.path in config['traps'] and request.path != "/favicon.ico":
		# Preparing the alert message
		alertMessage = alert_msg(request, config)
		# Slack alert
		if config['alert']['slack']['enabled'] == "true":
			WEBHOOK_URL = config['alert']['slack']['webhook-url']
			slack_alerter(alertMessage, WEBHOOK_URL)
		# Email alert
		if config['alert']['email']['enabled'] == "true":
			email_alerter(alertMessage, config)
		# SMS alert
		if config['alert']['twilio']['enabled']== "true":
			sms_alerter(alertMessage, config)
		#TODO: HTTP Endpoint Support
	# Honeypot event logs
	if request.headers.getlist("X-Forwarded-For"):
		source_ip = request.headers.getlist("X-Forwarded-For")[0]
	else:
		source_ip = request.remote_addr
	logger.info('{{"sourceip":"{}","host":"{}","request":"{}","http_method":"{}","body":"{}","user_agent":"{}"}}'.format(
		source_ip, request.url_root, request.full_path, request.method, request.data, request.user_agent.string))
	# Prepare and send the custom HTTP response
	contype, body = generate_http_response(request, config)
	# Customize the response using a template (in case you want to return a dynamic response, etc.)
	# You can comment the next 2 lines if you don't want to use this. /Just an example/
	if body == "custom.html":
		return (render_template(body, browser = request.user_agent.browser, ua = request.user_agent.string))
	return (send_file(body, mimetype=contype) if "image" in contype else render_template(body))

def load_config():
	""" Load the configuration file """
	CONFIGFILE = os.environ.get('configFile')
	# Load config from the local file
	with open('config.json') as config_file:
		conf = json.load(config_file)
		logger.info("--> Local config file loaded")

	return conf

# About
@app.route('/about')
def about():
    return render_template('about.html')

# 404 Error Page
# @app.errorhandler(404)
# def page_not_found(e):
#     # note that we set the 404 status explicitly
# 	# http://flask.pocoo.org/docs/1.0/patterns/errorpages/
#     return render_template('404.html'), 404

# Articles
@app.route('/articles')
def articles():
    # Create cursor
    cur = mysql.connection.cursor()

    # Get articles
    result = cur.execute("SELECT * FROM articles")

    articles = cur.fetchall()

    if result > 0:
        return render_template('articles.html', articles=articles)
    else:
        msg = 'No Articles Found'
        return render_template('articles.html', msg=msg)
    # Close connection
    cur.close()

#Single Article
@app.route('/article/<string:id>/')
def article(id):
    # Create cursor
    cur = mysql.connection.cursor()

    # Get article
    result = cur.execute("SELECT * FROM articles WHERE id = %s", [id])

    article = cur.fetchone()

    return render_template('article.html', article=article)


# Register Form Class
class RegisterForm(Form):
    name = StringField('Name', [validators.Length(min=1, max=50)])
    username = StringField('Username', [validators.Length(min=4, max=25)])
    email = StringField('Email', [validators.Length(min=6, max=50)])
    password = PasswordField('Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Passwords do not match')
    ])
    confirm = PasswordField('Confirm Password')


# User Register
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm(request.form)
    if request.method == 'POST' and form.validate():
        name = form.name.data
        email = form.email.data
        username = form.username.data
        password = sha256_crypt.encrypt(str(form.password.data))

        # Create cursor
        cur = mysql.connection.cursor()

        # Execute query
        cur.execute("INSERT INTO users(name, email, username, password) VALUES(%s, %s, %s, %s)", (name, email, username, password))

        # Commit to DB
        mysql.connection.commit()

        # Close connection
        cur.close()

        flash('You are now registered and can log in', 'success')

        return redirect(url_for('login'))
    return render_template('register.html', form=form)


# User login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Get Form Fields
        username = request.form['username']
        password_candidate = request.form['password']

        # Create cursor
        cur = mysql.connection.cursor()

        # Get user by username
        result = cur.execute("SELECT * FROM users WHERE username = %s", [username])

        if result > 0:
            # Get stored hash
            data = cur.fetchone()
            password = data['password']

            # Compare Passwords
            if sha256_crypt.verify(password_candidate, password):
                # Passed
                session['logged_in'] = True
                session['username'] = username

                flash('You are now logged in', 'success')
                return redirect(url_for('dashboard'))
            else:
                error = 'Invalid login'
                return render_template('login.html', error=error)
            # Close connection
            cur.close()
        else:
            error = 'Username not found'
            return render_template('login.html', error=error)

    return render_template('login.html')

# Check if user logged in
def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash('Unauthorized, Please login', 'danger')
            return redirect(url_for('login'))
    return wrap

# Logout
@app.route('/logout')
@is_logged_in
def logout():
    session.clear()
    flash('You are now logged out', 'success')
    return redirect(url_for('login'))

# Dashboard
@app.route('/dashboard')
@is_logged_in
def dashboard():

	# Load Config
    config=load_config()
    alertMessage = alert_msg(request, config)

    # Create cursor
    cur = mysql.connection.cursor()

    # Show articles only from the user logged in
    result = cur.execute("SELECT * FROM articles WHERE author = %s", [session['username']])

    currentUser =  [session['username']]
    trapUsers = []

	# TODO: Check that this is working properly without bugs
    for key, value in config.items():
        for num, name in value.items():
            trapUsers.append(name)


    articles = cur.fetchall()
    if currentUser[0] in trapUsers:
        #Send alert
        WEBHOOK_URL = config['alert']['slack']['webhook-url']
        slack_alerter(alertMessage, WEBHOOK_URL)
        sms_alerter(alertMessage, config)

        # Check if trapUser user has written anything
        if result > 0:
            return render_template('dashboard.html', articles=articles)
        else:
            msg = 'No Articles Found'
            return render_template('dashboard.html', msg=msg)

    elif result > 0:
        return render_template('dashboard.html', articles=articles)

    else:
        msg = 'No articles found'
        return render_template('dashboard.html', msg=msg)

    # Close connection
    cur.close()

# Article Form Class
class ArticleForm(Form):
    title = StringField('Title', [validators.Length(min=1, max=200)])
    body = TextAreaField('Body', [validators.Length(min=30)])


# Add Article
@app.route('/add_article', methods=['GET', 'POST'])
@is_logged_in
def add_article():
    form = ArticleForm(request.form)
    if request.method == 'POST' and form.validate():
        title = form.title.data
        body = form.body.data

        # Create Cursor
        cur = mysql.connection.cursor()

        # Execute
        cur.execute("INSERT INTO articles(title, body, author) VALUES(%s, %s, %s)",(title, body, session['username']))

        # Commit to DB
        mysql.connection.commit()

        #Close connection
        cur.close()

        flash('Article Created', 'success')

        return redirect(url_for('dashboard'))

    return render_template('add_article.html', form=form)


# Edit Article
@app.route('/edit_article/<string:id>', methods=['GET', 'POST'])
@is_logged_in
def edit_article(id):
    # Create cursor
    cur = mysql.connection.cursor()

    # Get article by id
    result = cur.execute("SELECT * FROM articles WHERE id = %s", [id])

    article = cur.fetchone()
    cur.close()
    # Get form
    form = ArticleForm(request.form)

    # Populate article form fields
    form.title.data = article['title']
    form.body.data = article['body']

    if request.method == 'POST' and form.validate():
        title = request.form['title']
        body = request.form['body']

        # Create Cursor
        cur = mysql.connection.cursor()
        app.logger.info(title)
        # Execute
        cur.execute ("UPDATE articles SET title=%s, body=%s WHERE id=%s",(title, body, id))
        # Commit to DB
        mysql.connection.commit()

        #Close connection
        cur.close()

        flash('Article Updated', 'success')

        return redirect(url_for('dashboard'))

    return render_template('edit_article.html', form=form)

# Delete Article
@app.route('/delete_article/<string:id>', methods=['POST'])
@is_logged_in
def delete_article(id):
    # Create cursor
    cur = mysql.connection.cursor()

    # Execute
    cur.execute("DELETE FROM articles WHERE id = %s", [id])

    # Commit to DB
    mysql.connection.commit()

    #Close connection
    cur.close()

    flash('Article Deleted', 'success')

    return redirect(url_for('dashboard'))

def generate_http_response(req, conf):
	""" Generate HTTP response """

	args = ["{}={}".format(key, value) for key, value in request.args.items()]
	path = req.path
	con_type = None
	body_path = None
	if path in conf['traps']:
		# Check if the token is defined and has a custom http response
		for token in args:
			if (token in conf['traps'][path]) and ("token-response" in conf['traps'][path][token]):
				con_type = conf['traps'][path][token]['token-response']['content-type']
				body_path = conf['traps'][path][token]['token-response']['body']
		# if the 'body_path' is still empty, use the trap/uri response (if there's any)
		if ("trap-response" in conf['traps'][path]) and body_path is None:
			con_type = conf['traps'][path]['trap-response']['content-type']
			body_path = conf['traps'][path]['trap-response']['body']
	# Load the default HTTP response if the 'body_path' is None
	if body_path is None:
		con_type = conf['default-http-response']['content-type']
		body_path = conf['default-http-response']['body']

	return con_type, body_path

def alert_msg(req, conf):
	""" Prepare alert message dictionary """

	# Message fields
	url_root = req.url_root
	full_path = req.full_path
	path = req.path
	data = req.data
	http_method = req.method
	useragent_str = req.user_agent.string
	browser = req.user_agent.browser
	browser_version = req.user_agent.version
	browser_lang = req.user_agent.language
	platform = req.user_agent.platform
	headers = "{}".format(req.headers)
	args = ["{}={}".format(key, value) for key, value in request.args.items()]
	# X-Forwarded-For: the originating IP address of the client connecting to the Heroku router
	if req.headers.getlist("X-Forwarded-For"):
		source_ip = req.headers.getlist("X-Forwarded-For")[0]
	else:
		source_ip = req.remote_addr

	# Search the config for the token note
	note = None
	if path in conf['traps']:
		# Check if the token is defined and has note
		for token in args:
			if (token in conf['traps'][path]) and ("token-note" in conf['traps'][path][token]):
				note = conf['traps'][path][token]['token-note']
		# If the 'note' is still empty, use the trap/uri note (if there's any)
		if ("trap-note" in conf['traps'][path]) and note is None:
			note = conf['traps'][path]['trap-note']

	#TODO: Threat Intel Lookup (Cymon v2)

	# Message dictionary
	msg = {
		"token-note": note if note else "None",
		"host": url_root,
		"path": full_path if full_path else "None",
		"http-method": http_method,
		"token": args[0] if args else "None", #Only the first arg
		"body": data if data else "None",
		"source-ip": source_ip,
		"user-agent": useragent_str,
		"browser": browser if browser else "None",
		"browser_version": browser_version if browser_version else "None",
		"browser_lang": browser_lang if browser_lang else "None",
		"platform": platform if platform else "None",
		"http-headers": headers
		#"threat-intel": threat_intel
	}

	return msg


def email_alerter(msg, conf):
	""" Send Email alert """

	smtp_server = conf['alert']['email']['smtp_server']
	smtp_port = conf['alert']['email']['smtp_port']
	smtp_user = conf['alert']['email']['smtp_user']
	smtp_password = conf['alert']['email']['smtp_password']
	to_email = conf['alert']['email']['to_email']
	subject = 'Honeyku Alert'
	now = time.strftime('%a, %d %b %Y %H:%M:%S %Z', time.localtime())
	body = ("Honeytoken triggered!\n\n"
			"Time: {}\n"
			"Source IP: {}\n"
			#"Threat Intel Report: {}\n"
			"User-Agent: {}\n"
			"Token Note: {}\n"
			"Token: {}\n"
			"Path: {}\n"
			"Host: {}").format(
		now,
		msg['source-ip'],
		#msg['threat-intel'] if msg['threat-intel'] else "None",
		msg['user-agent'],
		msg['token-note'],
		msg['token'],
		msg['path'],
		msg['host'])
	email_text = "From: {}\nTo: {}\nSubject: {}\n\n{}".format(
		smtp_user,
		", ".join(to_email),
		subject,
		body)

	try:
		server = smtplib.SMTP(smtp_server, smtp_port)
		server.ehlo()
		server.starttls()
		server.login(smtp_user, smtp_password)
		server.sendmail(smtp_user, to_email, email_text)
		server.close()
		logger.info("Email alert is sent")
	except smtplib.SMTPException as err:
		logger.error("Error sending email: {}".format(err))


def sms_alerter(msg, conf):
	""" Send SMS alert """
	config = load_config()
	account_sid = config['alert']['twilio']['sid']
	auth_token = config['alert']['twilio']['auth_token']
	client = Client(account_sid, auth_token)

	now = time.strftime('%a, %d %b %Y %H:%M:%S %Z', time.localtime())

	message = client.messages \
					.create(
						body=("Honeytoken triggered!\n\n"
								"Time: {}\n\n"
								"Source IP: {}\n\n"
								#"Threat Intel Report: {}\n"
								"User-Agent: {}\n\n"
								"Token Note: {}\n\n"
								"Token: {}\n\n"
								"Path: {}\n\n"
								"Host: {}").format(
							now,
							msg['source-ip'],
							#msg['threat-intel'] if msg['threat-intel'] else "None",
							msg['user-agent'],
							msg['token-note'],
							msg['token'],
							msg['path'],
							msg['host']),
						from_='+447492882057',
	                     	to='+447710532369'
					)


	logger.info("--> SMS alert is sent")
	logger.info("--> "+message.sid+"\n")


def slack_alerter(msg, webhook_url):
	""" Send Slack alert """

	now = time.strftime('%a, %d %b %Y %H:%M:%S %Z', time.localtime())
	# Preparing Slack message
	slack_message = {
		"text": "*Honeytoken triggered!*\nA honeytoken has been triggered by {}".format(msg['source-ip']),
		"username": "honeyku",
		"icon_emoji": ":ghost:",
		"attachments": [
			{
				"color": "danger",
				# "title": "Alert details",
				"text": "Alert details:",
				"footer": "honeyku",
				"footer_icon": "https://raw.githubusercontent.com/0x4D31/honeyLambda/master/docs/slack-footer.png",
				"fields": [
					{
						"title": "Time",
						"value": now,
						"short": "true"
					},
					{
						"title": "Source IP Address",
						"value": msg['source-ip'],
						"short": "true"
					},
					#{
					#	"title": "Threat Intel Report",
					#	"value": msg['threat-intel'] if msg['threat-intel'] else "None",
					#},
					{
						"title": "Token",
						"value": msg['token'],
						"short": "true"
					},
					{
						"title": "Token Note",
						"value": msg['token-note'],
						"short": "true"
					},
					{
						"title": "Host",
						"value": msg['host'],
						"short": "true"
					},
					{
						"title": "Path",
						"value": msg['path'],
						"short": "true"
					},
					{
						"title": "Browser",
						"value": msg['browser'],
						"short": "true"
					},
					{
						"title": "Browser Version",
						"value": msg['browser_version'],
						"short": "true"
					},
					{
						"title": "Platform",
						"value": msg['platform'],
						"short": "true"
					},
					{
						"title": "HTTP Method",
						"value": msg['http-method'],
						"short": "true"
					},
					{
						"title": "User-Agent",
						"value": msg['user-agent']
					}
					#{
					#	"title": "HTTP Headers",
					#	"value": msg['http-headers']
					#}
				]
			}
		]
	}

	# Sending Slack message
	req = urllib.request.Request(webhook_url, data=json.dumps(slack_message).encode('utf8'))

	try:
		resp = urllib.request.urlopen(req)
		logger.info("--> Slack alert is sent\n")
	except urllib.error.HTTPError as err:
		logger.error("Request failed: {} {}".format(err.code, err.reason))
	except urllib.error.URLError as err:
		logger.error("Connection failed: {}".format(err.reason))

	return


if __name__ == '__main__':
	app.secret_key='mysecret123'
	app.run(debug=True, use_reloader=True)
