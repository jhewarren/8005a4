# Cover
BCIT Comp 8505
Assignment 4
DNS Spoofing


by:
John Warren
A00087379

for:
Aman Abdulla

due:
    Oct 22, 2018 - 11am

# TOC
<automated>

# Introduction
For this assignment you are required to implement a DNS spoofing application. This is primarily a POC application. All that is required as acceptable functionality is web site spoofing.

# Requirements
## Objective
To design a basic DNS spoofing application using any language of your choice. 

## Constraints
Your application will simply sense an HTML DNS Query and respond with a crafted Response answer, which will direct the target system to a your own web site.
• You will test this POC on a LAN on your own systems only. This means that you are not to carry out any DNS spoofing activity on unsuspecting client systems.
• You are required to handle any arbitrary domain name string and craft a spoofed Response. 

## Deliverables
Submit a zip file containing all the code and documents as described below in the sharein folder for this course under “Assignment #4”.
• Submit a complete, zipped package that includes your report, tools that you used, and any supporting data (dumps, etc), and references. Test results, complete with supporting data such as screen shots and traffic dumps
• Hand in complete and well-documented design work and documents in PDF format.
• Also provide all your source code and an executable.
• You are required to demo this assignment in the lab.

## Due 
November 5, 1100 hrs. 

# Evaluation
Design:                                          5 /  5
Documentation (explanation, user guide, etc):    5 /  5
Testing and Supporting Data:                    10 / 10
Functionality:                                  30 / 30
                                        Total:  50 / 50

# Implementation
## Analysis
determine target
poison arp table
Answer as milliways
deliver DNS response
capture arp & dns transactions from lab
reference base packets when crafting spoof packets

## Design
### Pseudo Code
Main Loop
---------
parse parameters
confirm user is root
get 
pthread - ARP poison gw
pthread - ARP poison target
listen for filter match
dns spoof
pthread - join (x2)
exit

ARP Poisoning
-------------
build struct 
connect to socket
fill arp struct
fill ethernet struct
fill device struct
build packet
send packet(n times, f frequency, t delay)
exit
    
DNS Spoofing
------------
build struct 
connect to socket
while !sigint
    sniff for dns packets
    grab header data
    grab packet data
    build header data
    build packet data
send response
exit

## Testing
ARP
---
modify packet format, any change in results

DNS
---
modify packet format, any change in results


## Results

# Appendix
## References
https://www.sans.org/reading-room/whitepapers/dns/dns-spoofing-man-middle-1567
http://milliways.bcit.ca/c8505/dnsspoof.pdf
## Tools
## Reports
## Source Code
