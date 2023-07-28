# IP-Sweeper-Nmap-Scanner
## A Python program that sweeps a /24 subnet and scans any live hosts on the network!

### Introduction
This is a personal project I made to put some of my Python skills to the test, expirement with networking libraries, and gain a better understanding of nmap. The concept for this tool is simple yet effective: look for all of the IPs on a subnet, scan the ones that are online, and then store each IP scan into a file the user can come back to later. It was a fun little project that does its job!

### Requirements
This tool requires the following libraries: socket, time, sys, os, and nmap

### Syntax and Usage
This tool was made for ethical and legal uses only. Any other such use is not approved, unethical, and possibly illegal. 

The tool is required to run as root or by using `sudo`. This is because the nmap scan runs and grabs operating system information of the live hosts on the network, which requires `sudo` or root to run. An example case of running this tool is `sudo python3 SweepScan.py 192.168.10.10`. 
