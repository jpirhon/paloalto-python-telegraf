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
    logging.info('Parsing firewall %s (%s) cpu info', firewall)
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
def parse_output(firewall, unixtime, resource_info):
    # Get the XML Element Tree
    resource_info_tree = ET.fromstring(resource_info.content)

    # Assign some help variables
    cpu_count = 0
    total_cpu_avg = 0
    total_cpu_avg_calc = 0
    dp_cores = 0

    # Calculate the total CPU amount
    for resource in resource_info_tree.findall(".//dp0/minute/cpu-load-average"):
        cpu_count = len(list(resource))

    # Get resource info and parse
    for resource in resource_info_tree.findall(".//dp0"):
        # Calculate and print average CPU info
        for cpu in resource.findall("./minute/cpu-load-average/entry"):
            if (cpu_count - int(cpu.find('coreid').text)) != cpu_count:
                if (cpu_count > 2) and (cpu_count - int(cpu.find('coreid').text)) == 1: 
                    pass
                elif int(cpu.find('coreid').text) > 12:
                    pass
                else:
                    dp_cores += 1
                    total_cpu_avg += int(cpu.find('value').text)
                    print("pacpuinfo,firewall=" + firewall + ",cpuid=" + cpu.find('coreid').text + " cpu-avg=" + cpu.find('value').text + " " + str(unixtime))

        # Calculate average CPU from all dataplane cores
        total_cpu_avg_calc = total_cpu_avg / dp_cores
        print("pacpuinfo,firewall=" + firewall + ",cpuid=all cpu-avg=" + str(total_cpu_avg_calc) + " " + str(unixtime))
        total_cpu_avg_calc = 0
        total_cpu_avg = 0
        dp_cores = 0

        # Calculate and print maximum CPU info
        for cpu in resource.findall("./minute/cpu-load-maximum/entry"):
            if (cpu_count - int(cpu.find('coreid').text)) != cpu_count:
                if (cpu_count > 2) and (cpu_count - int(cpu.find('coreid').text)) == 1: 
                    pass
                elif int(cpu.find('coreid').text) > 12:
                    pass
                else:
                    print("pacpuinfo,firewall=" + firewall + ",cpuid=" + cpu.find('coreid').text + " cpu-max=" + cpu.find('value').text + " " + str(unixtime))

        # Print resource-utilization
        for sess_info in resource.findall("./minute/resource-utilization/entry"):
            if sess_info.find('name').text == "packet buffer (average)":
                print("pacpuinfo,firewall=" + firewall + ",packet_buffer=packet_buffer_avg packet_buffer_avg=" + sess_info.find('value').text + " " + str(unixtime))
            elif sess_info.find('name').text == "packet buffer (maximum)":
                print("pacpuinfo,firewall=" + firewall + ",packet_buffer=packet_buffer_max packet_buffer_max=" + sess_info.find('value').text + " " + str(unixtime))

def main():
    # Print help to CLI and parse the arguments
    parser=argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent('''\
            Palo Alto Get CPU and packet buffer info for Telegraf
        '''))
    parser.add_argument('-f', type=str, dest='firewall_db', default="firewalls.json", help='File to read the firewall database from')
    args=parser.parse_args()

    # Config filenames
    config_filename = "config.json"
    firewall_filename = args.firewall_db
    unixtime = time.time_ns()

    # Output logging information for debug purposes
    logging.info('Starting Palo Alto Get CPU info for telegraf')
    logging.info('Parsing config %s and firewall database %s', config_filename, firewall_filename)

    # Parse configuration files
    config = parse_config(config_filename)
    fw_config = parse_config(firewall_filename)

    # Initiate jobs list
    jobs = []

    try:
        # Parse firewalls list
        for firewall in fw_config["firewalls"]: 
            # Save the function calls into jobs list
            thread_apicall = threading.Thread(target=pa_apicall, args=(firewall["ip"], "op", "<show><running><resource-monitor><minute><last>1</last></minute></resource-monitor></running></show>", config["apikey"], firewall["name"], unixtime))
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
