# Author: Dr. X
# look for open ports based on list ports.csv or ports_small.csv
# count number of ports per type of device, write to file

import shodan
import time
import datetime
import Shodan_setup 

# Configuration
api = Shodan_setup.get_API_key()

# read devices from file
devices_data, exploits_data, ports_data = Shodan_setup.read_input_files()

output_file_name = './data/ports' + str(datetime.datetime.now()) + '.csv'
output_file = open(output_file_name, 'w')

# print header row in output file
output_file.write('Device Type, Device Model')
for port_item in ports_data:
        output_file.write(', ' + port_item)
output_file.write('\n')

# print port results in output file
for dev_item in devices_data:
        for model in devices_data[dev_item]:
                # print device type, model, and how many devices were found
                try:
                        results = api.search(model)
                        output_file.write(dev_item + ', ' + model + ', ' + str(results['total']))
                except Exception as e:
                        print(e)
                # print ports per device model
                for port_item in ports_data:
                        for port in ports_data[port_item]:
                                try:
                                        num_ports = api.search(model + ' port ' + port)
                                        output_file.write(', ' + str(num_ports['total']))
                                        time.sleep(20)
                                except Exception as e:
                                        print(e)
                # done with csv line
                output_file.write('\n')

output_file.close()