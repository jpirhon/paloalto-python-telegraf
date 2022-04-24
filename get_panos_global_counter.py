#!/usr/bin/env python
import datetime
import logging
import requests
import json
import time
import urllib3
import argparse
import textwrap
import threading
import xml.etree.ElementTree as ET

sem = threading.Semaphore()

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logging.basicConfig(level=logging.WARNING, format='[%(asctime)s] [%(levelname)s] (%(threadName)-10s) %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

# Set the API Call URL
PAOpApiCallUrl = "https://{}/api/?type={}&cmd={}&key={}"

# Function for parsing the configuration
def parse_config(config_path):
    with open(config_path, 'r') as config_file:
        config_data = json.load(config_file)
    return config_data

# Palo Alto API call function
def pa_apicall(url,calltype,cmd,key,firewall,unixtime):
    logging.info('Parsing firewall %s (%s) system info', firewall)

    result = requests.get(PAOpApiCallUrl.format(url, calltype, cmd, key), verify=False, timeout=5)

    if result.status_code != 200:
        logging.info("Palo Alto API call failed - status code: %i" % r.status_code)
        return 1

    # Acquire semaphore and parse the output
    sem.acquire()
    parse_output(firewall, unixtime, result)
    sem.release()

    return 1

# Parse and print output
def parse_output(firewall, unixtime, gc_info):
    # Get the XML Element Tree
    gc_info_tree = ET.fromstring(gc_info.content)

    # Parse the Global Counter info from the XML Tree and print it in InfluxDB output format
    for gc in gc_info_tree.findall(".//entry"):
        print("paglobalcounters,firewall=" + firewall + "," + "counter=" + gc.find('name').text + " value=" + gc.find('value').text + " " + str(unixtime))


def main():
    # Print help to CLI and parse the arguments
    parser=argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent('''\
            Palo Alto Get Global Counters info for Telegraf
        '''))
    parser.add_argument('-f', type=str, dest='firewall_db', default="firewalls.json", help='File to read the firewall database from')
    args=parser.parse_args()

    # Config filenames
    config_filename = "config.json"
    firewall_filename = args.firewall_db
    unixtime = time.time_ns()

    # Output logging information for debug purposes
    logging.info('Starting Palo Alto Get Global Counters info for Telegraf')
    logging.info('Parsing config %s and firewall database %s', config_filename, firewall_filename)

    # Parse configuration files
    config = parse_config(config_filename)
    fw_config = parse_config(firewall_filename)

    # Initiate jobs list
    jobs = []

    try:
        # Parse the firewalls list
        for firewall in fw_config["firewalls"]: 
            # Save the function calls into jobs list
            # We are getting the severity "drop" counters. Change the severity to get events of lesser severity
            thread_apicall = threading.Thread(target=pa_apicall, args=(firewall["ip"], "op", "<show><counter><global><filter><severity>drop</severity></filter></global></counter></show>", config["apikey"], firewall["name"], unixtime))
            jobs.append(thread_apicall)

        # Start the jobs in list
        for j in jobs:
            j.start()
         
        # Join the jobs in list
        for j in jobs:
            j.join()

    except KeyboardInterrupt:
        logging.info('KeyboardInterrupt')

    logging.info('Ending')

if __name__ == "__main__":
    main()
