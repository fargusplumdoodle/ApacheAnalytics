#!/usr/bin/python3

import sys
import os
import csv
import re
import requests
import json

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
VERBOSE = True
ARGS = sys.argv
try:
    APACHE_LOG = sys.argv[1]
    OUTPUT_CSV = sys.argv[2]
except IndexError:
    print(DOCUMENTATION)
    print("Error: Invalid number of arguments, expected 2")
    exit(1)

# For apache logs,  1: IPv4 address
REQUEST_REGEX = r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) - - \[(\d\d\/\w{1,3}/\d{4}).*$'

# for getting client information
IP_API_URL = "http://ip-api.com/json/"

# for writing to the CSV
CSV_HEADER = ['date', 'ip', 'requests', 'country', 'city', 'entity']

class DayClient:
    """
    This object will be used to keep track of how many requests are from who
    for each day
    """
    # ip address of client
    ip = None

    # day of which requests were made
    day = None

    # country of IP
    country = None
    # city of IP
    city = None
    # "as" field from ip-api. This is usually just the ISP if its a
    # real user. However if there is an organization, this will be
    # the organization
    entity = None

    # number of requests by this client on this day
    requests = None

    def get_row(self):
        return [
            self.day,
            self.ip,
            self.requests,
            self.country,
            self.city,
            self.entity
        ]


def validate():
    """
    Validates input, exits if input is invalid

    Procedure:
        1. Check log file exists
    """
    # 1
    if not os.path.isfile(APACHE_LOG):
        print(DOCUMENTATION)
        print("Error: log file doesnt exist")
        exit(2)


def get_client_info(dayclient: DayClient) -> DayClient:
    """
    Returns a dayclient object with the following attributes set
        country
        city
        entity

    :param dayclient: day client object with IP value set
    :return: dayclient
    """
    if dayclient.ip is None:
        print(DOCUMENTATION)
        print("ERROR: IP is not set on DayClient")
        exit(3)

    # making request to IP-API
    r = requests.get(str(IP_API_URL + dayclient.ip))

    if r.status_code != 200:
        print(DOCUMENTATION)
        print("ERROR: error requesting IP info from ip-api. Status code: %d" % r.status_code)
        exit(4)

    # if something is wrong here the whole program will crash, I dont think that is an issue
    response = json.loads(r.content)

    dayclient.city = response["city"]
    dayclient.country = response["country"]
    dayclient.entity = response["as"]

    return dayclient


def get_logs() -> list:
    """
    This function generates a list of requests

    for each request in the apache log, there will be a tuple in this list.

    This doesn't worry about counting each request for each day, so this will
    be a long list. With many duplicates entries.

    This does ignore all requests from "::1" and "127.0.0.1"

    :return: list of tuples: [(ip, day), (ip, day), ...]
    """
    # for testing how good our regular expression is
    invalid = 0
    valid = 0

    # opening the file
    with open(APACHE_LOG, 'r') as log:
        # for recording the requests
        request_events = []

        # looping through the log
        for line in log:

            # in the apache logs, there are some IPv6 internal requests
            # we dont care about those.
            if line[:3] == "::1":
                continue

            # testing this line against our regular expression
            match = re.match(REQUEST_REGEX, line)

            if match:
                try:
                    ip = match.group(1)
                    date = match.group(2)
                except:
                    invalid += 1
                    if VERBOSE:
                        print("ERROR: match error with : %s" % line)

                # skipping internal requests
                if ip != "127.0.0.1":
                    request_events.append((ip, date))
                    valid += 1
            else:
                # this line wasn't matched, we will record this
                invalid += 1
                if VERBOSE:
                    print("WARN: Unable to match: %s" % line)
    if VERBOSE:
        print("get_logs: identified %d requests, unable to parse %d" % (valid, invalid))

    return request_events


def count_requests(requests: list) -> dict:
    """
    This function generates a list of DayClient objects and returns them
    :requests: list of tuples from "get_logs"
    :return: dictionary, key=tuple of ('ip addr', 'date') value=number of requests on that date
    """
    # for keeping track of the number of requests per day
    num_requests = {}

    # looping through all requests
    for request in requests:

        # if we have already recorded a request from this client on this day, we increment
        # the number of requests for that client on that day, otherwise this is the first
        # request we are seeing from that client on this day and we set the number of requests
        # from that client to 1
        if request in num_requests:
            num_requests[request] += 1
        else:
            num_requests[request] = 1

    return num_requests


def generate_day_clients(requests_per_client) -> list:
    """
    This function takes a dictionary like:
        dictionary, key=tuple of ('ip addr', 'date') value=number of requests on that date

    and generates the day client list for the CSV file

    :param requests_per_client:
    :return: list of DayClient objects
    """
    dayclients = []
    for day in requests_per_client:
        dayclient = DayClient()

        dayclient.ip = day[0]
        dayclient.date = day[1]
        dayclient.requests = requests_per_client[day]

        # populating the rest of the fields
        dayclient = get_client_info(dayclient)

        dayclients.append(dayclient)

    return dayclients


def write_csv(dayclients):
    """
    This function writes a csv
    :param dayclients: list of dayclient objects
    """
    with open(OUTPUT_CSV, mode='w') as output_csv:
        # opening csv file
        csv_fl = csv.writer(output_csv, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)

        # writing header
        csv_fl.writerow(CSV_HEADER)

        for dayclient in dayclients:
            csv_fl.writerow(dayclient.get_row())


if __name__ == "__main__":
    validate()

    requests_events = get_logs()

    requests_per_client = count_requests(requests_events)

    dayclients = generate_day_clients(requests_per_client)

    write_csv(dayclients)
