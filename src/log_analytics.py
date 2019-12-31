#!/usr/bin/python3

import sys

DOCUMENTATION = """
-------------
LOG ANALYTICS
-------------

Arguments:
    1. Path to Apache2 access log file
    2. Path to output csv 
    
Description:
    Generates a CSV from apache logs that shows the number of requests 
    per day from each client as well as some additional information on the 
    client. 
"""

if __name__ == "__main__":

