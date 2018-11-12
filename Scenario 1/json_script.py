#!/usr/bin/python3.6

# -*- coding: utf-8 -*-
"""
@author: othornew
"""

# Import packages
import json
import sys
import os
import datetime


def json_format(text):
    # It's difficult to import the JSON file directly so I'll first load it as a string into python
    with open('cowrie.json', 'r') as f:
        json_data = f.readlines()
    print("There are", len(json_data), "json entries")

    # If we take seperate items from the list, we can parse it into JSON
    json.loads(json_data[0])
    print("loaded json_data", 'Preparing for analysis \n')

    # The JSON data structure is practically the same as the Python Dictionary, so if we can load them step by step
    # then we can comebine them into a single one using a dictionary

    # Init a new Python Dictionary for JSON
    json_dict = {}

    for i, j in enumerate(json_data):
        k = json.loads(json_data[i])

        # Save to dictionary
        json_dict[i] = k

    # Save file
    with open('formatted_cowrie.json', 'w') as fp:
        json.dump(json_dict, fp)


def login_attempts(text):
	"""login attempts"""
	json_file = open("formatted_cowrie.json", "r", encoding="utf-8")
	data = json.load(json_file)
	json_file.close()
	# print (json_data)
	for i in data.values():
		if 'login' in i['eventid']:
			if 'success' in i['eventid']:
				print("** Successful Credentials:", i["username"], '/', i["password"], '\n',
				"      IP Address:", i['src_ip'], '\n',
				"      Time:", datetime.datetime.strptime(i['timestamp'][:-8], '%Y-%m-%dT%H:%M:%S'))
				print()
			else:
				print("!! Failed attempts", i["username"], '/', i["password"], '\n',
				"      IP Address:", i['src_ip'], '\n',
				"      Time:", datetime.datetime.strptime(i['timestamp'][:-8], '%Y-%m-%dT%H:%M:%S'), '\n')

def commands(text):
	"""IP addresses seen"""
	json_file = open("formatted_cowrie.json", "r", encoding="utf-8")
	data = json.load(json_file)
	json_file.close()
	for i in data.values():
		if 'input' in i['eventid']:
			print("Command used:",i['input'], "from",  i['src_ip'], '\n',
			"   time:", datetime.datetime.strptime(i['timestamp'][:-8], '%Y-%m-%dT%H:%M:%S'), '\n')

def session_activity(text):
	"""Find session activity"""
	json_file = open("formatted_cowrie.json", "r", encoding="utf-8")
	data = json.load(json_file)
	json_file.close()
	for i in data.values():
		if i['session'] == i['session']: # Of course this will always result in True; need to figure out a solution
			print (i['session'])


def main():
	if os.path.isfile('formatted_cowrie.json'):
		sys.argv.append('formatted_cowrie.json')

	print("Analyzing file:", sys.argv[1])
	json_format(sys.argv[1])
	login_attempts(sys.argv[1])
	#commands(sys.argv[1])
	session_activity(sys.argv[1])


if __name__ == '__main__':
    main()
