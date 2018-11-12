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
		    "src_ip": "192.168.217.131",
		    "session": "6fac825b1545"
		  	},
	   	"4": {
		    "eventid": "login.failed",
		    "username": "george",
		    "password": "hello",
		    "message": "login attempt [george/hello] failed",
		    "sensor": "ubuntu",
		    "timestamp": "2018-11-11T14:01:32.376158Z",
		    "src_ip": "192.168.217.131",
		    "session": "6fac825b1545"
		  	}
		}


for i in data.values():
	if 'login' in i['eventid']:
		if 'success' in i['eventid']:
			#print(i)
			print("***Successful Credentials:",i["username"],'/', i["password"])
		else:
			print("Failed attempts",i["username"],'/', i["password"])


