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
### srcip
Source IP address
### sport
Source port number
### dstip
Dest IP address
### dsport
Dest port number
### proto
Transaction protocol
### state
The state and its dependent protocol, e.g. ACC, CLO, else (-)
### dur 
Record total duration
### sbytes
Source to destination bytes 
### dbytes
Destination to source bytes
### sttl
Source to destination time to live 
### dttl
Destination to source time to live
### sloss
Source packets retransmitted or dropped 
### dloss
Destination packets retransmitted or dropped 
### service
http, ftp, ssh, dns ..,else (-)
### sload
Source bits per second
### dload
Destination bits per second
### spkts
Source to destination packet count 
### dpkts
Destination to source packet count 
### swin
Source TCP window advertisement
### dwin
Destination TCP window advertisement
### stcpb
Source TCP sequence number
### dtcpb
Destination TCP sequence number
### smeansz
Mean of the flow packet size transmitted by the src
### dmeansz
Mean of the flow packet size transmitted by the dst
### trans_depth
The depth into the connection of http request/response transaction
### reb_bdy_len
The content size of the data transferred from the server’s http service
### sjit
Source jitter (mSec)
### djit
Destination jitter (mSec)
### stime
Record start time
### ltime
Record last time
### sinpkt
Source inter-packet arrival time (mSec)
### dinpkt
Destination inter-packet arrival time (mSec)
### tcprtt
The sum of ’synack’ and ’ackdat’ of the TCP.
### synack
The time between the SYN and the SYN_ACK packets of the TCP
### ackdat
The time between the SYN_ACK and the ACK packets of the TCP
### is_sm_ips_ports 
If source (1) equals to destination (3)IP addresses and port numbers (2)(4) are equal, this variable takes value 1 else 0 
### ct_state_ttl
No. for each state (6) according to specific range of values for source/destination time to live (10) (11)
### ct_ftw_http_mthd
No. of flows that has methods such as Get and Post in http service (only get)
### is_ftp_login
If the ftp session is accessed by user and password then 1 else 0
### ct_ftp_cmd
No of flows that has a command in ftp session
### ct_srv_src
No. of connections that contain the same service (14) and source address (1) in 100 connections according to the last time (26)
### ct_srv_dst
No. of connections that contain the same service (14) and destination address (3) in 100 connections according to the last time (26)
### ct_dst_ltm
No. of connections of the same destination address (3) in 100 connections according to the last time (26)
### ct_src_ltm
No. of connections of the same source address (1) in 100 connections according to the last time (26)
### ct_src_dport_ltm
No of connections of the same source address (1) and the destination port (4) in 100 connections according to the last time (26)
### ct_dst_sport_ltm
No of connections of the same destination address (3) and the source port (2) in 100  connections according to the last time (26)
### ct_dst_src_ltm
No of connections of the same source (1) and the destination (3) address in in 100 connections according to the last time (26)
### attack_cat
The name of each attack category. In this data set, nine categories (e.g., Fuzzers, Analysis, Backdoors, DoS, Exploits, Generic, Reconnaissance, Shellcode and Worms)
### Label
0 for normal and 1 for attack records
### s_retrans
Source packets retransmitted
### d_retrans
Destination packets retransmitted
### m_int_s
For each connection the mean interval between two packets (Source - in mSec)
### m_int_d
For each connection the mean interval between two packets (Destination - in mSec)
### http_post
No. of flows that has method Post in http service 
### user_ftp
User ftp if request
### pwd_ftp
Password ftp if captured
