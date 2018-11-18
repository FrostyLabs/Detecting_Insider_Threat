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
