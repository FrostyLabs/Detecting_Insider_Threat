# Detecting Insider Threat Using Honey Tokens
Honours Project SOC10101 - Edinburgh Napier University 

This tool sets out to use deception based techniques to catch insider threat. Honeytokens are deployed as HTML comments within the intranet login page. When honeytokens are triggered an alert is sent and logged in JSON format. Alerts can be sent through Email, SMS, or through Slack. Logged alerts are analyzed under frequency analysis and provide a threat rating (high/medium/low). 

This project was inspired from Honeyku - https://github.com/0x4d31/honeyku



## Installation/Setup

Project developed in Python 3.6.7

#### Install Python Dependencies

Using the `requirements.txt` file in `/flask-app/`

```sh
$ pip3 install -r requirements.txt
```

#### Setup MySQL tables
Database is stored in MySQL. 
```sh
$ apt install mysql-server libmysqlclient-dev
```

Create tables using the `sql_tables.sql` file, located in `/flask-app/`
```sh
$ mysql -u ${username} -p
mysql> create database insiderThreat
mysql> --Create Tables
```


### Start Application

1. Configure using `config.json` located in `/flask-app/`
2. Insert database informaiton (`host`, `user`, `password`, `database`)

The application must be ran as super user otherwise the `arp_scan()` method cannot function. 
```sh
$ cd flaskapp
$ sudo python3 flaskapp.py
```

### Security
This app is not intended to be exposed on the internet.

