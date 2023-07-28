import socket
import time
import sys
import os
import nmap

# Initialize global variables that the program will be working with
live_hosts = []
nm = nmap.PortScanner()

# Perform error checking to make sure correct number of arguments are used
if len(sys.argv) == 2:
        usr_ip = sys.argv[1] #translate hostname to ipv4
else:
        print("[!] Error: invalid number of arguments!")
        print("[!] Syntax: python3 fishbowl.py your.ip.onthe.network")
        exit(1)

# Perform error checking by validating if the user given IP is an IP
try:
     socket.inet_aton(usr_ip)
except:
     print ("[!] Error: Not a valid IP address! Please enter your IPv4 address on the target network!")
     exit(2)

# This function simply grabs the time for when the function is called
def get_time():
      try:
        curr_time = time.localtime()
        formatted_curr_time = time.strftime("%H:%M:%S", curr_time)
        return formatted_curr_time
      except:
        print("[!] Error: Could not get the current time!")
        exit(3)

# This function performs a basic IP sweep of a /24 subnet
def find_live_hosts():
     try:
        print("[+] Looking for active hosts, this will take a minute...")
        #These three lines take the user IP the user has on the targeted network and removes the final octet to make it end in .0
        host_ip = usr_ip
        dot = host_ip.rfind(".")
        host_ip = host_ip[0:dot+1]
     except:
        print("[!] Error: Could not get the broadcast address of your IP.")
        print("[!] Please make sure you are using the right IP address (ex: 192.168.128.57)")
        exit(4)
     # This for loop iterates through every IP on the network and pings it once
     for i in range(1, 255):
        try:
             host = host_ip + str(i)
             response = os.system("ping -c 1 -w 1 " + host + " >/dev/null") # Ping the IP on the network
             if response == 0 and host != usr_ip: # If the IP active on the network and if it is not the same as the user ip
                print(f"[-] {host} is online!") # Tell the user the IP is online
                live_hosts.append(host) # Add this IP to a list of live hosts
        except:
             print("[!] Error: Trouble detecting a live host! Please try again!")
             exit(5)
     if len(live_hosts) > 0:
        print(f"[+] {len(live_hosts)} of 254 found and online!") # Tell the user after the "IP sweep" is done how many hosts the program found alive on the network
     else:
        print("[!] No hosts online in the network!")
        exit(0)

# This function pulls all of the relevant and necessary information from the nmap scan and formats it into a readable form
def format_nmap_scan_results(scan_results):
    try:
        ip_address = scan_results['addresses']['ipv4'] # Grab the IP
        status = scan_results['status']['state'] # Grab the state of the port
        reason = scan_results['status']['reason'] # Grab the reason responses in the nmap scan for why nmap believes the host is active
        open_ports = scan_results['tcp'] # Grab all open ports from the nmap scan
        os_family = scan_results['osmatch'][0]['osclass'][0]['osfamily'] # Grab the OS family for the host in the scan
        os_name = scan_results['osmatch'][0]['name'] # Grab the OS name for the host in the scan
        type = scan_results['osmatch'][0]['osclass'][0]['type'] # Grab the type of host from the scan
    except:
         print("[!] Error: Could not grab information from the nmap scan!")
         exit(7)
    try:
        formatted_output = f"Time: {get_time()}\n" # Display the approximate time the scan was ran
        formatted_output += f"Host: {ip_address}\n"  # Display the host IP that was scanned
        formatted_output += f"Status: {status} ({reason})\n" # Display the status of the host at the time of the scan as well as the reason why nmap believes its status
        formatted_output += f"OS Family: {os_family}\n" # Display what family the OS belongs to (Linux, Windows, etc)
        formatted_output += f"OS Name: {os_name}\n" # Display the name of the OS
        formatted_output += f"Type: {type}\n\n" # Display what type of machine is running (proxy-server, firewall, etc)

        formatted_output += f"Host: {ip_address}\n" # Display the IP address of the host scanned
        formatted_output += f"Open Ports:\n" # Header for the open ports found in the scan
        for port, details in open_ports.items():
                formatted_output += f"   Port {port} ({details['name']})\n" # Displays the port and its name
                formatted_output += f"      State: {details['state']}\n" # Displays the state of the port
                formatted_output += f"      Service: {details['product']}\n" # Displays the service running on the port
                formatted_output += f"      Version: {details['version']}\n" # Displays the version running on the port
                formatted_output += f"      CPE: {details['cpe']}\n" # Displays CPE
                formatted_output += f"      Extra Info: {details['extrainfo']}\n" # Displays any extra info running on the port
    except:
         print("[!] Error: Details about the host could not be formatted!")
         exit(8)
    return formatted_output # Return the formatted output

# This function scans all of the hosts found in the live_hosts list
def scan_live_hosts():
      print("[+] Beginning nmap scans. Please stand by...") # Tell the user nmap scans are beginning
      for ip in live_hosts:
            try:
                print(f"[+] Scanning {ip}") # Tell the user a scan is starting
                nm.scan(ip,'1-65535', "-A -T3 -O") # This line tells nmap to perform an aggressive scan with three threads (T4 could result in missing something) and grabbing the OS information
                print("[-] Scan complete!") # Tell the user a scan is complete
            except:
                 print("[!] Error: An error occurred scanning the hosts!")
                 exit(6)
            try:
                 formatted_results = format_nmap_scan_results(nm[ip]) # Call the format_nmap_scan_results function to format the results from the scan
            except:
                 print("[!] Error: Could not format the results of the scan properly!")
                 exit(9)
            print("[-] Writing scan to file...") # Tell the user the scans are being written to a file
            try:
               folder_name = f"scan_results_{start_time}" # Create a directory name for the scan files to go into
               os.makedirs(folder_name, exist_ok=True) # Create the directory
               with open(f'{folder_name}/{ip}_scan.txt', 'w') as file: # Open or create a new text file with the name of the IP
                        file.write(formatted_results) # Add the formatted results from the format_nmap_scan_results function
            except:
                 print("[!] Error: Scan file could not be written!")
                 exit(10)
            print("[-] Scan has successfully been written to a file!") # Tell the user the scan was written successfully

# Banner informing the user of the start time and their IP they entered
start_time = get_time()
print("="*50)
print(f"Start time: {start_time}")
print(f"Your IP is: {usr_ip}")
print("="*50)

# The main functions of the program are called here
find_live_hosts() 
scan_live_hosts()

# Tell the user the scans are the complete
print("[+] Scans are complete!")

# Another banner to tell the user what time the program finished running at and to remind the user how many hosts there are on the subnet
print("="*50)
print(f"Finish time: {get_time()}")
print(f"Number of hive hosts: {len(live_hosts)}")
print("="*50)

# Exit the program gracefully
exit(0)