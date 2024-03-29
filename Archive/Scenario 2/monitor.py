#!/usr/bin/python3
"""
@author Brumo Rocha
	#http://brunorocha.org/python/watching-a-directory-for-file-changes-with-python.html
	#https://github.com/rochacbruno

"""

import sys
import time
from watchdog.observers import Observer
from watchdog.events import PatternMatchingEventHandler

class MyHandler(PatternMatchingEventHandler):
	patterns = ["*.txt", "*.docx"]

	def process(self, event):
		"""
		event.event_type
            'modified' | 'created' | 'moved' | 'deleted'
        event.is_directory
            True | False
        event.src_path
            path/to/observed/file
        """
		print (event.src_path, event.event_type)

	def on_modified(self, event):
		self.process(event)
		print("Time: ",time.asctime(),'\n')

	def on_created(self, event):
		self.process(event)
		print("Time: ",time.asctime(),'\n')

	def on_deleted(self, event):
		self.process(event)
		print("Time: ",time.asctime(),'\n')

	def on_moved(self, event):
		print(self.process(event))
		print("Time: ",time.asctime(),'\n')

	def on_copied(self, event):
		print(self.process(event))
		print("Time: ",time.asctime(),'\n')

if __name__ == '__main__':
	args = sys.argv[1:]
	observer = Observer()
	observer.schedule(MyHandler(), path=args[0] if args else '.')
	observer.start()

	try:
		while True:
			time.sleep(1)
	except KeyboardInterrupt:
		observer.stop()

	observer.join()
