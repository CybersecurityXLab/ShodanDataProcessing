# Author: Dr. X
# pre-processing functions needed for search and count IoTs

import shodan
import time
import datetime
import csv

def get_API_key():

    f = open("myKey.txt")
    myKey = f.readline()
    SHODAN_API_KEY = str(myKey)
    api = shodan.Shodan(SHODAN_API_KEY)
    return api

    f.close()

