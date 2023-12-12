# Zeek-Pcap-Features-Extractor
Zeek Package that extends the functionality of Zeek network analysis framework. This package automatically recognizes connection from (pcap) file and automatically extract features from it. The goal for the feature extraction is to describe an individual connection that occur in the pcap file as accurately as possible.

## Installation
To refresh the Zeek Package Manager and add the package, run the following command:
```
$ zkg refresh
```
To install the package using Zeek Package Manager, run the following command:
```
$ zkg install Zeek-Pcap-Features-Extractor
```
## Run
To extract the features on the selected pcap file that contains different connections, run the following command in a terminal:
```
$ zeek Zeek-Pcap-Features-Extractor -r file.pcap
```
or optionally:
```
$ zeek Zeek-Pcap-Features-Extractor -r file.pcap ignore_checksums=T
```
The output will be stored in multiple log files in zeek log format. The `fullLog.log` contains all the features extracted and looks like this:
```
$ #separator \x09
$ #set_separator  ,
$ #empty_field    (empty)
$ #unset_field    -
$ #path   fullLog
$ #open   2023-12-07-11-05-39
$ #fields ts  uid id.orig_h   id.orig_p   id.resp_h   id.resp_p   proto   service duration    orig_bytes  resp_bytes  conn_state  local_orig  local_resp  missed_bytes    history orig_pkts   orig_ip_bytes   resp_pkts   resp_ip_bytes   tunnel_parents  sload   dload   smeansz dmeansz trans_depth reb_bdy_len start_time  last_time   is_sm_ips_ports is_ftp_login    user_ftp    pwd_ftp ct_ftp_cmd  pkts_dropped_   sjit    djit    sinpkt  dinpkt
$ #types  string  string  addr    port    addr    port    enum    string  string  count   count   string  bool    bool    count   string  count   count   count   count   set[string] double  double  double  double  count   count   string  string  string  count   string  string  count   count   interval    interval    interval    interval
2023-01-23 21:52:10 Ctcnkh1AHaKnCbfish  185.175.0.3 59244   185.175.0.5 502 tcp modbus  0m0s    12  11  SF  -   -   0   ShADadFf    6   332 4   227 -   125476.218136   115019.866625   2.0 2.0 0   0   2023-01-23 21:52:10 2023-01-23 21:52:10 0   -   -   -   -   0   0.025494    0.000000    0.124872    0.157102
2023-01-23 21:52:10 CwOqfa3Ov8oO8eJm6l  185.175.0.3 59246   185.175.0.5 502 tcp modbus  0m0s    12  11  SF  -   -   0   ShADadFf    6   332 4   227 -   74017.129412    67849.035294    2.0 2.0 0   0   2023-01-23 21:52:10 2023-01-23 21:52:10 0   -   -   -   -   0   -0.001232   0.000000    0.001895    0.000500
$ #close  2023-12-07-11-06-17
```
The `flowFeatures.log` is:
```
#separator \x09
#set_separator  ,
#empty_field    (empty)
#unset_field    -
#path   flowFeatures
#open   2023-12-07-16-04-05
#fields id.orig_h   id.orig_p   id.resp_h   id.resp_p   proto
#types  addr    port    addr    port    enum
185.175.0.3 58040   185.175.0.5 502 tcp
185.175.0.3 58042   185.175.0.5 502 tcp
#close  2023-12-07-16-05-17
```
The `infoPackets.log` is represented as:
```
#separator \x09
#set_separator  ,
#empty_field    (empty)
#unset_field    -
#path   infoPackets
#open   2023-12-07-16-04-05
#fields stcpb   dtcpb   ttl win
#types  count   count   count   count
-   -   64  509
-   1   64  502
#close  2023-12-07-16-05-12
```
The `infoTCPConn.log` is described in the following way:
```
#separator \x09
#set_separator  ,
#empty_field    (empty)
#unset_field    -
#path   infoTCPConn
#open   2023-12-07-16-04-05
#fields synack  ackdat  tcprtt  m_int_s m_int_d
#types  interval    interval    interval    interval    interval
0.000000    0.000000    0.000000    0.000000    0.000000
0.000000    0.000026    0.000026    0.000004    0.000000
0.000000    0.000019    0.000019    0.000003    0.000000
#close  2023-12-07-16-05-12
```
The output on the `terminal` prints out:
```
-----------Feature 43-----------
There are 75 connections that have the same IP destination '185.175.0.8'
There are 3 connections that have the same IP destination '185.175.0.5'
There are 20 connections that have the same IP destination '185.175.0.4'
There is 1 connection that has the same IP destination '185.175.0.6'
----------------------------------------
```
## Description
Once the data was obtained from the network traffic capture, a process was performed to extract the features. We analyzed the pcap files that portray the network traffic of the ModBus dataset, we calculated and printed 63 features, of which 49 for each connection recorded within the pcap file and 14 inherent to all the connections taken overall.
To do this, we took advantage of the events and functions made available by Zeek, as well as custom functions (created on our own), to simplify the code or to calculate unknown data within the Zeek environment.

In addition, to make the most of the log files produced automatically by Zeek, we used Machine Learning algorithms to study and graph the occurrences and characteristics of the various attacks stored in pcap files of the ModBus dataset in the section relating to the attacks, called "attack".

## Extracted Features
All the features to extract are highlighted in the excel file, called "featureCyber" provided in the previous part together with the code.

## Extension (Python and Machine Learning)
First of all, it's important to parse a Zeek's log into Dataframe in python using Zat:
```python
import zat
from zat.log_to_dataframe import LogToDataFrame

# Create a Pandas dataframe from the Zeek HTTP log for example
log_to_df = LogToDataFrame()
zeek_df = log_to_df.create_dataframe('http.log')
print('Read in {:d} Rows...'.format(len(zeek_df)))
zeek_df.head()
```
The following example of code is explains how to train/fit and predict anomalous instances using the Isolation Forest model:
```python
odd_clf = IsolationForest(contamination=0.35)
odd_clf.fit(zeek_matrix)
```
The K-Means algorithm is a partitioning cluster analysis algorithm that allows the division of a set of objects into k groups based on their attributes. It is a variant of the Expectation-Maximization (EM) algorithm, aiming to determine the k groups of data generated by Gaussian distributions.

PCA, or Principal Component Analysis, is a dimensionality reduction technique designed to decrease the relatively high number of variables describing a dataset to a smaller set of latent variables, while minimizing information loss as much as possible.

These two concepts are used in the following example:
```python
# K-Means and PCA
kmeans = KMeans(n_clusters=3).fit_predict(odd_matrix)  # Change this to 3/5 for fun
pca = PCA(n_components=3).fit_transform(odd_matrix)

# Now we can put our ML results back onto our dataframe
odd_df['x'] = pca[:, 0] # PCA X Column
odd_df['y'] = pca[:, 1] # PCA Y Column
odd_df['cluster'] = kmeans
odd_df.head()
```
This is important to print out the observation of each cluster found:
```python
# Now print out the details for each cluster
pd.set_option('display.width', 1000)
for key, group in cluster_groups:
    print('\nCluster {:d}: {:d} observations'.format(key, len(group)))
    print(group[features].head())
```
