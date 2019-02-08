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

from flask import Flask, request, render_template, send_file, flash, redirect, url_for, session, logging, send_from_directory, abort
import logging
import sys
import os
import json
import datetime
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
import secrets
import re

app = Flask(__name__)

# Config MySQL
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = ''
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = ''
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
def default(path):
    return render_template('default.html')

@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'),
                               'favicon.ico', mimetype='image/vnd.microsoft.icon')

def load_config():
    """ Load the configuration file """
    CONFIGFILE = os.environ.get('configFile')
    # Load config from the local file
    with open('config.json') as config_file:
        conf = json.load(config_file)

    return conf

# About
@app.route('/about')
def about():
    return render_template('about.html')

# 404 Error Page
@app.errorhandler(404)
def page_not_found(e):
    # note that we set the 404 status explicitly
    # http://flask.pocoo.org/docs/1.0/patterns/errorpages/
    return render_template('404.html'), 404

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
    result = cur.execute("SELECT * FROM articles WHERE id = {}".format(id))

    article = cur.fetchone()

    return render_template('article.html', article=article)
    cur.close()


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
        try:
            cur.execute("INSERT INTO users(name, email, username, password) VALUES('{}', '{}', '{}', '{}')".format(name, email, username, password))

            # Commit to DB
            mysql.connection.commit()

            # Close connection
            cur.close()

            flash('You are now registered and can log in', 'success')

            return redirect(url_for('login'))
        except Exception as err:
            flash(err, 'danger')
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
        result = cur.execute("SELECT * FROM users WHERE username = '{}'".format(username))

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

    # Create cursor
    cur = mysql.connection.cursor()

    # Show articles only from the user logged in
    result = cur.execute("SELECT * FROM articles WHERE author = '{}'".format(session['username']))

    currentUser =  [session['username']]

    trapUsers = []

    for key, data in config.items():
        for category, info in data.items():
            if category == 'usernames':
                for id, name in info.items():
                    if name not in trapUsers:
                        trapUsers.append(name)

    articles = cur.fetchall()
    if currentUser[0] in trapUsers:
        alerter()

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
        cur.execute("INSERT INTO articles(title, body, author) VALUES('{}', '{}', '{}')".format(title, body, session['username']))

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
    result = cur.execute("SELECT * FROM articles WHERE id = {}".format(id))

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
        cur.execute ("UPDATE articles SET title='{}', body='{}' WHERE id={}".format(title, body, id))
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
    cur.execute("DELETE FROM articles WHERE id = {}".format(id))

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

# Alerter
@is_logged_in
def alerter():
    config=load_config()
    alertMessage = alert_msg(request, config)
    # Slack alert
    if config['alert']['slack']['enabled'] == "true":
        WEBHOOK_URL = config['alert']['slack']['webhook-url']
        slack_alerter(alertMessage, WEBHOOK_URL, session['username'])
    # Email alert
    if config['alert']['email']['enabled'] == "true":
        email_alerter(alertMessage, config, session['username'])
    # SMS alert
    if config['alert']['twilio']['enabled']== "true":
        sms_alerter(alertMessage, config, session['username'])
    # Logfile Alert
    if config['alert']['logfile']['enabled'] == "true":
        logfile_alerter(alertMessage, config, session['username'])

def email_alerter(msg, conf, usr):
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
            "Path: {}\n"
            "Host: {}\n"
            "Username: {}\n").format(
        now,
        msg['source-ip'],
        #msg['threat-intel'] if msg['threat-intel'] else "None",
        msg['user-agent'],
        msg['path'],
        msg['host'],
        usr)
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
        logger.info("--> Email alert is sent\n")
    except smtplib.SMTPException as err:
        logger.error("Error sending email: {}".format(err))


def sms_alerter(msg, conf, usr):
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
                                "Path: {}\n\n"
                                "Host: {}\n\n"
                                "Username: {}\n\n").format(
                            now,
                            msg['source-ip'],
                            #msg['threat-intel'] if msg['threat-intel'] else "None",
                            msg['user-agent'],
                            msg['path'],
                            msg['host'],
                            usr),
                        from_='+447492882057',
                             to='+447710532369'
                    )


    logger.info("--> SMS alert is sent. Message ID: "+message.sid+"\n")


def slack_alerter(msg, webhook_url, usr):
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
                    #    "title": "Threat Intel Report",
                    #    "value": msg['threat-intel'] if msg['threat-intel'] else "None",
                    #},
                    {
                        "title": "Host",
                        "value": msg['host'],
                        "short": "true"
                    },
                    {
                        "title": "Username",
                        "value": usr
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
                    #    "title": "HTTP Headers",
                    #    "value": msg['http-headers']
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

def logfile_alerter(msg, conf, usr):
    """Log alerts to file"""
    config = load_config()
    logPath = config['alert']['logfile']['path']
    logFile = config['alert']['logfile']['fname']
    now = time.strftime('%a, %d %b %Y %H:%M:%S %Z', time.localtime())

    # Find stored honey token
    try:
        cur = mysql.connection.cursor()

        # Get tokens
        tokenSearch = "SELECT username FROM users WHERE username LIKE 'dev%'"
        tokens = cur.execute(tokenSearch)

        deployedToken = cur.fetchall()

        cur.close()

        dictToken = deployedToken[0]
        #username = dictToken.get('username')
        deployedTokenValue = dictToken.get('username')
    except Exception as e:
        logger.info(e)

    # Check of file exists
    if os.path.isfile(logPath+logFile):
        # Check if file is valid json
        try:
            with open(logPath+logFile) as f:
                logsFile = json.load(f)
            # JSON is valid, continue
            # Create new log
            newLog = {"Honey token triggered - "+now: {
                                         "Current Deployed Token": deployedTokenValue,
                                         "src-ip": msg['source-ip'],
                                         "User-Agent": msg['user-agent'],
                                         "Path": msg['path'],
                                         "Host": msg['host'],
                                         "Time": now,
                                         "User": usr
                                         }
                     }

            # Update existing JSON
            logsFile.update(newLog)

            # Write to file
            with open(logPath+logFile, 'w') as f:
                json.dump(logsFile, f, indent=2)

            logger.info("--> Added log to logs file ({}{})\n".format(logPath, logFile))

        except ValueError as e:
            logger.info("--> File is not valid JSON. Error: {} \n".format(e))
            # have to try and write file and log
            logger.info("--> If the file is empty, delete it. \n")
    else:
        # Create new log
        newLog = {"Honey token triggered - "+now: {
                                     "Current Deployed Token": deployedTokenValue,
                                     "src-ip": msg['source-ip'],
                                     "User-Agent": msg['user-agent'],
                                     "Path": msg['path'],
                                     "Host": msg['host'],
                                     "Time": now,
                                     "User": usr
                                     }
                 }

        # Write log to file
        with open(logPath+logFile, 'w') as f:
            json.dump(newLog, f, indent=2)

        logger.info("---> Created Log file ({}{}) and added log\n".format(logPath, logFile))

@app.route('/honey-deploy')
@is_logged_in
def honeyDeploy():
    """Do some things"""
    currentUser =  [session['username']]

    if currentUser[0] == 'admin':
        config = load_config()
        tokenUsers = []
        tokenPassw = []



        for key, data in config.items():
            for category, info in data.items():
                if category == 'usernames':
                    for id, name in info.items():
                        if name not in tokenUsers:
                            tokenUsers.append(name)

                if category == 'passwords':
                    for num, passwd in info.items():
                        if passwd not in tokenPassw:
                            tokenPassw.append(passwd)

        tokenUser = secrets.choice(tokenUsers)
        plainPass = secrets.choice(tokenPassw)
        encPass = sha256_crypt.encrypt(str(plainPass))

        cur = mysql.connection.cursor()
        try: # Try to check if there are existing honey tokens
            # Regex find already deployed honey token
            regex = r"<!--(.*?)-->"
            htmlFile = open ('templates/login.html')
            htmlFileVar = htmlFile.read()
            htmlFile.close()
            matches = re.findall(regex, htmlFileVar)

            if matches: # if HTMl comtains bait
                try: #try to insert into db
                    #Delete already existing user
                    cur.execute("DELETE FROM users where username like 'dev%'")
                    mysql.connection.commit()

                    cur.execute("INSERT INTO users(username, password) VALUES ('{}', '{}')".format(tokenUser, encPass))
                    mysql.connection.commit()
                    cur.close()

                except Exception as e:
                    logger.info(e)
                    flash('Check console', 'danger')

                try: #Try to insert into HTML
                    file = open('templates/login.html', 'w')
                    file.write(re.sub(regex, "<!-- Development Account // Username: {} // Password: {} -->".format(tokenUser, plainPass), htmlFileVar))
                    file.close()

                except Exception as e:
                    logger.info(e)
                    flash('Check console', 'danger')

                flash('Honeytoken in HTML and DB replaced', 'success')
            else:
                try:
                    cur.execute("DELETE FROM users WHERE username LIKE 'dev%'")
                    mysql.connection.commit()

                    cur.execute("INSERT INTO users(username, password) VALUES ('{}', '{}')".format(tokenUser, encPass))
                    mysql.connection.commit()
                    cur.close()

                except Exception as e:
                    logger.info(e)
                    flash('Check console', 'danger')
                try:
                    with open('templates/login.html', 'r+') as f:
                        lines = f.readlines()
                        f.seek(0)
                        lines.insert(5, '\n  <!-- Development Account // Username: {} // Password: {} -->\n'.format(tokenUser, plainPass))
                        f.writelines(lines)

                except Exception as e:
                    logger.info(e)
                    flash('Check console', 'danger')

                flash('Brand new honey token inserted to DB and HTML', 'success')

        except Exception as e:
            logger.info(e)
            flash(e, 'danger')

        return render_template('honey-deploy.html')
    else:
        flash('Unauthorized, Please login', 'danger')
        return redirect(url_for('login'))


def analyze_logfile():
    config = load_config()

    logFile = config['alert']['logfile']['path'] + config['alert']['logfile']['fname']

    with open(logFile) as f:
        lFile = json.load(f)

    numberDict = {}

    for key, value in lFile.items():
        if value["src-ip"] not in numberDict:
            numberDict[value["src-ip"]] = []
        time = value["Time"]
        cutTime = time[:-4]
        convTime = datetime.datetime.strptime(cutTime, "%a, %d %b %Y %H:%M:%S")
        now = datetime.datetime.now()
        since = now - convTime
        numberDict[value["src-ip"]].append(since)

    for IP, value in numberDict.items():
        ftCount = 0
        sCount = 0
        tCount = 0
        # print("Tokens logged by {}:".format(IP))
        for item in value:
            if 8 <= item.days <= 14:
                ftCount += 1
            if 4 <= item.days <= 7:
                sCount += 1
            if item.days <= 3:
                tCount += 1

        # print("{} has logged {} tokens in the past 14 days".format(IP, ftCount))
        # print("{} has logged {} tokens in the past  7 days".format(IP, sCount))
        # print("{} has logged {} tokens in the past  3 days\n".format(IP, tCount))

        try:
            cur = mysql.connection.cursor()
            cur.execute("DELETE FROM stats WHERE ip_addr = '{}'".format(IP))
            totalCount = ftCount+sCount+tCount
            # print("Total: {}".format(ftCount+sCount+tCount))
            cur.execute("INSERT INTO stats(ip_addr, two_weeks, one_week, three_days, total) VALUES('{}', {}, {}, {}, {})".format(IP, ftCount, sCount, tCount, totalCount))
            mysql.connection.commit()
            cur.close()
        except Exception as err:
            print(err)

    logger.info('Stats records up to date')



@app.route('/statistics')
@is_logged_in
def stats_page():
    currentUser =  [session['username']]
    analyze_logfile()

    if currentUser[0] == 'admin':
        try:
            # Create cursor
            cur = mysql.connection.cursor()

            # Get stats
            result = cur.execute("SELECT * FROM stats")

            stats = cur.fetchall()

            cur.close()

            return render_template('statistics.html', stats=stats)

        except Exception as err:
            logger.info(err)

    else:
        flash('Unauthorized, Please login', 'danger')
        return redirect(url_for('login'))

@app.route('/delete_stat/<string:ip>', methods=['POST'])
@is_logged_in
def delete_stat(ip):
    currentUser = [session['username']]

    if currentUser[0] == 'admin':
        # Try to delete value from MySQL
        try:
            cur = mysql.connection.cursor()
            cur.execute("DELETE FROM stats WHERE ip_addr = '{}'".format(ip))

            mysql.connection.commit()
            cur.close()

            logger.info('Stat {} deleted from database'.format(ip))

        except Exception as err:
            logger.info(err)
            flash('Problems deleting records from database', 'danger')
            return redirect(url_for('dashboard'))

        # Try to delete value from logfile.json
        try:
            config = load_config()
            logFile = config['alert']['logfile']['path'] + config['alert']['logfile']['fname']

            with open(logFile) as f:
                lFile = json.load(f)

            json_after_deleting = {k: v for k, v in lFile.items() if v['src-ip'] != ip}

            with open(logFile, 'w') as f:
                json.dump(json_after_deleting, f, indent=2)

            logger.info('Stat {} deleted from {}'.format(ip, logFile))

        except Exception as err:
            logger.info(err)
            flash('Problems deleting records from logfile.json', 'danger')
            return redirect(url_for('dashboard'))

        flash('Successfully deleted statistics for IP: {}'.format(ip), 'success')

        return redirect('/statistics')


    else:
        flash('Unauthorized, Please login', 'danger')
        return redirect(url_for('login'))

@app.route('/threats')
@is_logged_in
def threats():
    analyze_logfile()
    currentUser = [session['username']]

    if currentUser[0] == 'admin':
        try:
            cur = mysql.connection.cursor()

            result = cur.execute("SELECT ip_addr, total FROM stats")

            statValues = cur.fetchall()
            cur.close()

            return render_template('threats.html', stats=statValues)

        except Exception as err:
            logger.info(err)

    else:
        flash('Unauthorized, Please login', 'danger')
        return redirect(url_for('login'))

def secretKey():
    """Secret token generated to avoid hard coded secret key"""
    key = secrets.token_hex(16)
    return key

@app.before_request
def csrf_protect():
	if request.method == "POST":
		token = session.pop('_csrf_token', None)
		if not token or token != request.form.get('_csrf_token'):
			abort(403)

def generate_csrf_token():
	if '_csrf_token' not in session:
		session['_csrf_token'] = secretKey()
	return session['_csrf_token']


if __name__ == '__main__':
    app.jinja_env.globals['csrf_token'] = generate_csrf_token
    app.secret_key=secretKey()
    app.run(host='0.0.0.0', port=3000, debug=True, use_reloader=True)
