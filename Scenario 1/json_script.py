#!/usr/bin/python3.6

# -*- coding: utf-8 -*-
"""
@author: othornew
"""

# Import packages
import json
import sys


def json_format(text):
    # It's difficult to import the JSON file directly so I'll first load it as a string into python
    with open('cowrie.json', 'r') as f:
        json_data = f.readlines()
    print("There are", len(json_data), "json entries")

    # If we take seperate items from the list, we can parse it into JSON
    json.loads(json_data[0])
    print("loaded json_data", '\n\n\n\n')

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





def main():
    print("Analyzing file:", sys.argv[1])
    json_format(sys.argv[1])


if __name__ == '__main__':
    main()
