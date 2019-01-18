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
    print(sys.argv[1], 'successfully loaded! \nPreparing for analysis \n')

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

    print('Successfully formatted the file:', sys.argv[1], '\nSaved under \'formatted_cowrie.json\'')
    print('\nPlease re-run this script ')


def login_attempts(formatted_json):
	"""login attempts"""
	json_file = open(formatted_json, "r", encoding="utf-8")
	data = json.load(json_file)
	json_file.close()

	successes = 0
	failures = 0

	for i in data.values():
		if 'login' in i['eventid']:
			if 'success' in i['eventid']:
				successes = successes + 1
				print("** Successful Credentials:", i["username"], '/', i["password"], '\n',
				"   IP Address:", i['src_ip'], '\n',
				"   Time:", datetime.datetime.strptime(i['timestamp'][:-8], '%Y-%m-%dT%H:%M:%S'))
				print()
			elif 'failed' in i['eventid']:
				failures = failures + 1
				print("!! Failed attempts", i["username"], '/', i["password"], '\n',
				"   IP Address:", i['src_ip'], '\n',
				"   Time:", datetime.datetime.strptime(i['timestamp'][:-8], '%Y-%m-%dT%H:%M:%S'), '\n')

	print("--> Successful Logins", successes)
	print("--> Failed Logins", failures)

def commands(formatted_json):
	"""IP addresses seen"""
	json_file = open(formatted_json, "r", encoding="utf-8")
	data = json.load(json_file)
	json_file.close()

	commands = 0

	for i in data.values():
		if 'input' in i['eventid']:
			commands = commands + 1
			print("Command used: \n ",i['input'], "from",  i['src_ip'], '\n',
			"   time:", datetime.datetime.strptime(i['timestamp'][:-8], '%Y-%m-%dT%H:%M:%S'), '\n')

	print("Number of commands:", commands)


def group_session_id(formatted_json):
	"""This function groups the json data by session value"""
	print('*** Starting group by session ID \n')

	json_file = open(formatted_json, "r", encoding="utf-8")
	data = json.load(json_file)
	json_file.close()

	grouped_session = {}
	for log in data.values():
		session_id = log['session']
		if session_id not in grouped_session:
			grouped_session[session_id] = []
		grouped_session[session_id].append(log)

	print('- The number of unique sessions:', len(grouped_session),'\n')

def group_ip(formatted_json):
	"""This function will group by IP address with the aim of being able to count the number of times an IP address has accessed the honeypot"""

	print('*** IP Address Analysis\n')

	json_file = open(formatted_json, 'r', encoding='utf-8')
	data = json.load(json_file)
	json_file.close()

	grouped_ip = {}
	for log in data.values():
		ip_addr = log['src_ip']
		if ip_addr not in grouped_ip:
			grouped_ip[ip_addr] = []
		grouped_ip[ip_addr].append(log)

	print('- Number of unique IP addresses:',len(grouped_ip),'\n')

	counts = {}
	"""Counts number of sessions per IP address"""
	for key, value in grouped_ip.items():
	    counts[key] = 0
	    unique_session = []
	    for event in value:
	        for x,y in event.items():
	            if x == "session":
	                if y not in unique_session:
	                    unique_session.append(y)
	                    counts[key] += 1
	    print("- src_ip ({}) had : ({}) sessions".format(key, counts[key]))



# def session_activity(text):
# Not yet complete
# 	"""Find session activity"""
# 	print('\n Session Activity \n')


def main(): #run by ./json_script.py cowrie.json
	"""Main function"""
	print("--> Analyzing file:", sys.argv[1], '\n')
	print('--> Checking if relevant files exist')
	if os.path.isfile('formatted_cowrie.json'):
		sys.argv.append('formatted_cowrie.json')
		login_attempts(sys.argv[2])
		print('\n\n')
		commands(sys.argv[2])
		print('\n')
		group_session_id(sys.argv[2])
		# Not yet complete
		#session_activity(sys.argv[2])
		group_ip(sys.argv[2])
	else:
		json_format(sys.argv[1])


if __name__ == '__main__':
    main()
