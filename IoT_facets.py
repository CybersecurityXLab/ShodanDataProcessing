#!/usr/bin/env python
#
# query-summary.py
# Search Shodan and print summary information for the query.
#
# Author: achillean
# Modified by Dr. X to perform queries for different devices and add top ten ports, osses, devices, and CPEs

import shodan
import sys
import datetime
import Shodan_setup 

# Configuration
api = Shodan_setup.get_API_key()

# The list of properties we want summary information on
FACETS = [
    'org',
    'domain',
    ('port', 10),
    'asn',
    ('os', 10),
    'cpe',
    'device',

    # We only care about the top 3 countries, this is how we let Shodan know to return 3 instead of the
    # default 5 for a facet. If you want to see more than 5, you could do ('country', 1000) for example
    # to see the top 1,000 countries for a search query.
    ('country', 3),
]

FACET_TITLES = {
    'org': 'Top 5 Organizations',
    'domain': 'Top 5 Domains',
    'port': 'Top 10 Ports',
    'asn': 'Top 5 Autonomous Systems',
    'os': 'Top 10 Operating Systems',
    'cpe': 'Top 5 Common Platform Enumeration',
    'device': 'Top 5 Devices',
    'country': 'Top 3 Countries',
}

# read devices from file
devices_data, exploits_data, ports_data = Shodan_setup.read_input_files()

output_file_name = './data/facets' + str(datetime.datetime.now()) + '.txt'
output_file = open(output_file_name, 'w')

count = 1
for dev_item in devices_data:
    output_file.write('Type of device: ' + dev_item + '\n')
    for model in devices_data[dev_item]:
        try:
            query = model
            output_file.write('Query number:' + str(count) + '\n')
            count = count + 1

            # Use the count() method because it doesn't return results and doesn't require a paid API plan
            # And it also runs faster than doing a search().
            result = api.count(query, facets=FACETS)

            output_file.write('Shodan Summary Information \n')
            output_file.write('Query: %s' % query)
            output_file.write('\n')
            output_file.write('Total Results: %s\n' % result['total'])
            output_file.write('\n')

            # Print the summary info from the facets
            for facet in result['facets']:
                output_file.write(FACET_TITLES[facet] + '\n')

                for term in result['facets'][facet]:
                    output_file.write('%s: %s' % (term['value'], term['count'])+ '\n')

                # Print an empty line between summary info
                output_file.write('\n')
            # model query delimiter
            output_file.write('==========================================================\n')

        except Exception as e:
            print('Error: %s' % e)
            sys.exit(1)
    # device type query delimiter
    output_file.write('++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n')
        
output_file.close()