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

def read_input_files():
    input_file_devices = './hosts/devices_small.csv'
    input_file_ports = './attributes/ports_small.csv'
    input_file_exploits = './attributes/exploits.csv'
    exploits_data = dict()
    devices_data = dict()
    ports_data = dict()

    with open(input_file_devices, 'r') as csv_file_devs:
        reader = csv.reader(csv_file_devs)
        for row in reader:
            devices_data[row[0]] = (row[1:])

    with open(input_file_exploits, 'r') as csv_file:
        reader = csv.reader(csv_file)
        for row in reader:
            exploits_data[row[0]] = (row[1:])

    with open(input_file_ports, 'r') as csv_file_ports:
        reader = csv.reader(csv_file_ports)
        for row in reader:
            ports_data[row[0]] = (row[1:])

    return devices_data, exploits_data, ports_data