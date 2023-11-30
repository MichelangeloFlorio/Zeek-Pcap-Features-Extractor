# Zeek-Pcap-Features-Extractor
Zeek Package that extends the functionality of Zeek network analysis framework. This package automatically recognizes IRC communication in a packet capture (pcap) file and automatically extract features from it. The goal for the feature extraction is to describe an individual IRC communications that occur in the pcap file as accurately as possible.

## Installation
To install the package using Zeek Package Manager, run the following command:
```
$ zkg install zeek/stratosphereips/zeek-package-IRC
```
## Run
To extract the IRC features on the selected pcap file that contains IRC, run the following command in a terminal:
```
$ zeek -r file.pcap test1.zeek ignore_checksums=T
```
## Description

## Extracted Features
### Source IP address
### Source port number
### Dest IP address
### Dest port number
### Transaction protocol
### The state and its dependent protocol, e.g. ACC, CLO, else (-)
### Record total duration
### Source to destination bytes 
### Destination to source bytes
### Source to destination time to live 
### Destination to source time to live
### Source packets retransmitted or dropped 
### Destination packets retransmitted or dropped 
### http, ftp, ssh, dns ..,else (-)
### Source bits per second
### Destination bits per second
### Source to destination packet count 
### Destination to source packet count 
### Source TCP window advertisement
### Destination TCP window advertisement
### Source TCP sequence number
### Destination TCP sequence number
### Mean of the flow packet size transmitted by the src
### Mean of the flow packet size transmitted by the dst
### The depth into the connection of http request/response transaction
### The content size of the data transferred from the server’s http service
### Source jitter (mSec)
### Destination jitter (mSec)
### Record start time
### Record last time
### Source inter-packet arrival time (mSec)
### Destination inter-packet arrival time (mSec)
### The sum of ’synack’ and ’ackdat’ of the TCP.
### The time between the SYN and the SYN_ACK packets of the TCP
### The time between the SYN_ACK and the ACK packets of the TCP
### If source (1) equals to destination (3)IP addresses and port numbers (2)(4) are equal, this variable takes value 1 else 0 
### No. for each state (6) according to specific range of values for source/destination time to live (10) (11)
### No. of flows that has methods such as Get and Post in http service (only get)
### If the ftp session is accessed by user and password then 1 else 0
### No of flows that has a command in ftp session
### No. of connections that contain the same service (14) and source address (1) in 100 connections according to the last time (26)
### No. of connections that contain the same service (14) and destination address (3) in 100 connections according to the last time (26)
### No. of connections of the same destination address (3) in 100 connections according to the last time (26)
### No. of connections of the same source address (1) in 100 connections according to the last time (26)
### No of connections of the same source address (1) and the destination port (4) in 100 connections according to the last time (26)
### No of connections of the same destination address (3) and the source port (2) in 100  connections according to the last time (26)
### No of connections of the same source (1) and the destination (3) address in in 100 connections according to the last time (26)
### The name of each attack category. In this data set, nine categories (e.g., Fuzzers, Analysis, Backdoors, DoS, Exploits, Generic, Reconnaissance, Shellcode and Worms)
### 0 for normal and 1 for attack records
### Source packets retransmitted
### Destination packets retransmitted
### For each connection the mean interval between two packets (Source - in mSec)
### For each connection the mean interval between two packets (Destination - in mSec)
### No. of flows that has method Post in http service 
### User ftp if request
### Password ftp if captured
