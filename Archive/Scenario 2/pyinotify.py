#!/usr/bin/python3
"""
#source https://github.com/seb-m/pyinotify
"""
import pyinotify #pip3 install pyinotify
import sys
import time

wm = pyinotify.WatchManager()

#watched events
mask = pyinotify.IN_CREATE | pyinotify.IN_DELETE |  pyinotify.IN_MODIFY | pyinotify.IN_CLOSE_WRITE | pyinotify.IN_OPEN

class EventHandler(pyinotify.ProcessEvent):

	## TODO:
	#Make it so that it only shows specific file types (e.g. "*.txt")
	#More comprehensive output
	#Further analyse log output

	def process_IN_CREATE(self, event):
		print("--> Creating:\n ", event.pathname,"\n  Time:", time.asctime(), "\n")

	def process_IN_DELETE(self, event):
		print("--> Deleting:\n ", event.pathname,"\n  Time:", time.asctime(), "\n")

	def process_IN_MODIFY(self, event):
		print("--> Modifying:\n "+event.pathname+"\n  Time:", time.asctime(),'\n')

	def process_IN_CLOSE_WRITE(self, event):
		print("--> Close write:\n ", event.pathname,'\n  Time:', time.asctime(),'\n')

	def process_IN_OPEN(self, event):
		print("--> Opening:\n  "+event.pathname,'\n  Time:', time.asctime(),'\n')

def main():
	#watch_dir = input("Which directory do you you want to observe?\n")
	handler = EventHandler()
	notifier = pyinotify.Notifier(wm, handler)
	#wdd = wm.add_watch(watch_dir, mask, rec=True)
	wdd = wm.add_watch('/home/thomas/Desktop/restricted', mask, rec=True)

	notifier.loop()

if __name__ == '__main__':
	main()
