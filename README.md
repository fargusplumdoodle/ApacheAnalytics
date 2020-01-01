# Apache Analytics
For gathering information from apache logs for insight on how our webservices are used
and a general idea on who is using them.

### log_analytics
filename: log_analytics.py

Generates a CSV from an Apache log file with the following information:
 - how many requests from each client per day
 - what country/city is each client in
 
 This script uses a service called ip-api, check them out at 
 https://ip-api.com
