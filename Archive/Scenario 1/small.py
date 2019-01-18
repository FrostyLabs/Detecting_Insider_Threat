#!/usr/bin/python3.6

"""
This python script is only using a small set of data.
The point of this script is to simply be a proof of concept file, allowing me to try different methods

@author: othornew
"""

import json


data ={
		"1": {
			"eventid": "login.success",
		    "username": "sam",
		    "password": "p4ssw0rd",
		    "message": "login attempt [sam/p4ssw0rd] succeeded",
		    "sensor": "ubuntu",
		    "timestamp": "2018-11-11T13:50:53.064183Z",
		    "src_ip": "192.168.217.131",
		    "session": "1eeaaf20904f"
			},
		"2": {
			"eventid": "command.input",
		    "input": "ls -la",
		    "message": "CMD: ls -la",
		    "sensor": "ubuntu",
		    "timestamp": "2018-11-11T13:51:01.293303Z",
		    "src_ip": "192.168.217.131",
		    "session": "1eeaaf20904f"
			},
		"3": {
		    "eventid": "login.failed",
		    "username": "george",
		    "password": "george",
		    "message": "login attempt [george/george] failed",
		    "sensor": "ubuntu",
		    "timestamp": "2018-11-11T14:01:24.658923Z",
		    "src_ip": "192.168.123.131",
		    "session": "6fac825b1545"
		  	},
	   	"4": {
		    "eventid": "login.failed",
		    "username": "george",
		    "password": "hello",
		    "message": "login attempt [george/hello] failed",
		    "sensor": "ubuntu",
		    "timestamp": "2018-11-11T14:01:32.376158Z",
		    "src_ip": "192.168.123.131",
		    "session": "8fyh7635fh22"
		  	}
		}

"""
Grouping by session
"""
grouped = {}
for log in data.values():
	session_id = log['session']
	if session_id not in grouped:
		grouped[session_id] = []
	grouped[session_id].append(log)
#print (grouped,'\n')

"""
Another Grouping by session method
"""
from itertools import groupby
from operator import itemgetter

groupd = {
    group[0]: [log for log in group[1]]
    for group in groupby(
        [v for v in data.values()],
        key=itemgetter("session")
    )
}
#print(groupd, '\n')

"""
Grouping by IP
"""
grouped_ip = {}
for log in data.values():
	ip_addr = log['src_ip']
	if ip_addr not in grouped_ip:
		grouped_ip[ip_addr] = []
	grouped_ip[ip_addr].append(log)
#print(grouped_ip)



"""
Counting the logins per IP addresses
"""

count_logins = {}
for ip, nest_dic in grouped_ip.items():
	count_logins[ip] = 0
	for event in nest_dic:
		if event['eventid'] == 'login.success':
			count_logins[ip] += 1

#print(count_logins)

"""
Count the number of sessions per IP address
"""
count_sessions = {}
for ip, nest_dic in grouped_ip.items():
	count_sessions[ip] = 0
	for event['session'] in nest_dic:
		count_sessions[ip] +=1

# Problem with this is that the session does not count if unique
#print('Number of sessions:', count_sessions)




"""
Counting unique
"""

d =  {
 	'192.168.217.131': [
 		{'eventid': 'login.success', 'message': 'login attempt [sam/********] succeeded', 'sensor': 'ubuntu', 'timestamp': '2018-11-11T13:50:53.064183Z', 'src_ip': '192.168.217.131', 'session': '1eeaaf20904f'},
 		{'eventid': 'command.input', 'input': 'ls -la', 'message': 'CMD: ls -la', 'sensor': 'ubuntu', 'timestamp': '2018-11-11T13:51:01.293303Z', 'src_ip': '192.168.217.131', 'session': '1eeaaf20904f'}
 	],
 	'192.168.123.131': [
 		{'eventid': 'login.failed', 'message': 'login attempt [george/********] failed', 'sensor': 'ubuntu', 'timestamp': '2018-11-11T14:01:24.658923Z', 'src_ip': '192.168.123.131', 'session': '6fac825b1545'},
 		{'eventid': 'login.failed', 'message': 'login attempt [george/********] failed', 'sensor': 'ubuntu', 'timestamp': '2018-11-11T14:01:32.376158Z', 'src_ip': '192.168.123.131', 'session': '8fyh7635fh22'}
 	]
}


count_unique_session = {}

for key, value in d.items():
	count_unique_session[key] = 0
	for event in value:
		unique_list = []
		if event['session'] not in unique_list:
			count_unique_session[key] += 1 #Again same problem as above, it is not counting unique values, rather simply counting when there is a session value (even if it is a duplicate it will count)


unique_counts = {}

for key, value in d.items(): # key = ip, value = 'eventid': 'login.success', etc
    unique_counts[key] = 0
    unique_session = []
    for event in value: # event is the dictionary of 'eventid':'login.success', etc
        for x,y in event.items(): # x is eventid, message y is login.success, login attempt
            if x == "session":
                if y not in unique_session:
                    unique_session.append(y) # appends when value not in list
                    unique_counts[key] += 1
    print("{} : {}".format(key, unique_counts[key]))

"""
Testing printing with colour
https://stackoverflow.com/questions/287871/print-in-terminal-with-colors
"""
class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

#Looking at possible colours
# print (bcolors.ENDC+"ENDC" )
# print(bcolors.OKGREEN+'Green')
# print(bcolors.OKBLUE+'Blue')
# print(bcolors.WARNING+'Warning')
# print(bcolors.FAIL+'Fail')
# print(bcolors.UNDERLINE+'Underline')
# #Testing it with my work
# print(bcolors.WARNING,count_logins)


#print(bcolors.OKBLUE,count_logins)
