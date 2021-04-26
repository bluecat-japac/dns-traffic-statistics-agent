#	DNS Traffic Statistic Agent

## 1. Architecture
![Architecture](images/system_architecture.PNG?raw=true)

- In which, the DNS packets are classified by:
	- Each DNS client IP address – from the incoming queries.
    - Each authoritative DNS server IP address – for the outgoing queries.

1. Sniffer:
	- Sniff the DNS packets on port 53 for the configured interface.
	- Then put the sniffed packets into Decoder module.
2. Decoder:
	- Process the message in single channel.
	- Then put the decoded packets into Statistics module
3. Statistics:
	- Create the map contains all interfaces of the running server.
	- Create the map to store all messages that belong to the client/AS.
	- When the message received, triggers the process to calculate and update the metrics.
	- At the end of the interval time:
		- Trigger the function to continue to do more extra process if need.
		- Export the statistics.
		- Prepare the message then send to the SNMP sub-agent via REST API.
		- Create the message queue to save the out message if there's issue when  sending to the SNMP sub-agent.
	- Check the message queue to see if any message need to be sent.
	- Limit the message in queue/disk by using interval time/number of items.
    - Note for Average response time calculation in Statistics module as following:
        - msg_1: avg = value_msg_1
        - msg_2: avg = (avg + value_msg_2)/2
        - msg_3: avg = (avg + value_msg_3)/3
        - msg_4: avg = (avg + value_msg_4)/4

4. New SNMP Sub-agent:
	- Be responsible to update value to MIB counters whenever receiving the statistics message sent from "Statistics" module in Packetbeat.
	- Collect Per-view statistics using URL provided by BIND statistics-channels and write to MIB counters

## 2. Setup 
 Can be setup either using Section 2.1 or 2.2</h2>
>Note:
> - Make sure that DNS service (named) is running so that DNS queries can be received and responded
> - Make sure SNMP service are running so that the dns statistic agent can register to the master SNMP agent.
## 2.1. Setup dns statistic agent docker container on BDDS 9.3 in ARM System

### Import a docker image from file named dns-traffic-statistics-agent-arm64.tar.gz (dns-traffic-statistics-agent-amd64.tar.gz if in AMD system)
- Download and copy dns-traffic-statistics-agent-arm64.tar.gz to BDDS system  
- Extract dns-traffic-statistics-agent-arm64.tar.gz file
- Go to dns-traffic-statistics-agent-arm64/images directory which have both dns_stat_agent.tar and dns_packetbeat.tar files.  
- Require to have docker installed in this Virtual Machine.
- Load images from zip files
  ```
  docker load -i dns_stat_agent.tar
  docker load -i dns_packetbeat.tar
  ```
  
### Run docker container from a docker image named dns_stat_agent
- Copy **BCN-DNS-AGENT-MIB.mib** into folder /usr/share/snmp/mibs and append "BCN-DNS-AGENT-MIB" end of /etc/snmp/snmp.conf.
- Run docker container:
  ```
  docker run --network=host -d --name dns_stat_agent -v /replicated/jail/named/etc/named.conf:/replicated/jail/named/etc/named.conf -v /var/agentx/master:/var/agentx/master -v /usr/share/snmp/mibs/:/usr/share/snmp/mibs/ -v /var/lib/snmp/mibs/iana/:/var/lib/snmp/mibs/iana/ -v /var/lib/snmp/mibs/ietf/:/var/lib/snmp/mibs/ietf/ dns_stat_agent:<tag> 
  ```
- Note: to mount dns_stat_agent_logs, use the following option:
  ```
  -v <dns_stat_agent_logs directories>:/var/log/dns_stat_agent/ 
  ```

### Run docker container from a docker image named dns_packetbeat
- In dns-traffic-statistics-agent-arm64/packetbeat/ there is announcement_bam_deploy.py file
- Open postDeploy.sh from the link /usr/local/bluecat/postDeploy.sh and add the following line at the bottom of this file: <br> 
   ```python2 <full path announcement_bam_deploy.py>```
- Run docker container:
  ```
  docker run --cap-add=NET_ADMIN --network=host -d --name dns_packetbeat -v /replicated/jail/named/etc/named.conf:/replicated/jail/named/etc/named.conf dns_packetbeat:<tag>
  ```
- Note:
  - To change config packetbeat, use the following option. Make sure to set permission for packetbeat.yml
  ```
  chmod go-w packetbeat/packetbeat.yml
  chown root:root packetbeat/packetbeat.yml
  -v <full path to packetbeat.yml>:/etc/packetbeat/packetbeat.yml
  ```
  - To mount packetbeat logs, use the following option:	
  ```
  -v <packetbeat_logs directories>:/var/log/packetbeat/
  ```
  - To change statistics_config.json, use the following option:
  ```
  -v <full path to statistics_config.json>:/usr/share/packetbeat/bin/statistics_config.json
  ```

## 2.2. Setup dns traffic statistic agent on BDDS 9.3 manually
## 2.2.1. Packetbeat installation and usage
Extract the dns-traffic-statistic-agent.tar.gz to a folder in BDDS, then follow the below steps:
### Compile
1. Install golang dependency
	```
	go get ./...
	```
2. Build
	```
	go build
	```
	
### Setup packetbeat service
1. Install packetbeat.deb in setup-package
	```
	dpkg -i packetbeat.deb
	```
- In dns-traffic-statistics-agent-arm64/packetbeat/ there is announcement_bam_deploy.py file
2. Open postDeploy.sh from the link /usr/local/bluecat/postDeploy.sh and add the following line at the bottom of this file: <br> 
   ```python2 <full path announcement_bam_deploy.py>``` 
   
## 2.2.2. SNMP Subagent installation and usage
### Running Packetbeat
1. Make sure the SNMP SubAgent started first
2. Running
	```
	/etc/init.d/packetbeat start
	```
## 2.2.3. SNMP Subagent

### Configure and install
1. Copy **BCN-DNS-AGENT-MIB.mib** into folder /usr/share/snmp/mibs and append "BCN-DNS-AGENT-MIB" end of /etc/snmp/snmp.conf.

2. Configure snmpd.conf. There are 2 options:
	- Enable and config snmp's information in BAM and deploy to BDDS.

3. Configure Master agent to plugin new sub-agent
- Before running python dns_stat_agent, need to configuare AGENT_CONFIGURATION in config.py matched host and port in snmpd.conf.
	- HTTP_CONFIGURATION:
	
	| Key  | Value |
	| ------------- | ------------- |
	| host  | IP address for http server [String]  |
	| port  | port of http server [integer]  |

	- AGENT_CONFIGURATION:
	
	| Key  | Value |
	| ------------- | ------------- |
	| agent_name  | The agent's name used for registration with net-snmp. [String]  |
	| master_socket  | defines the address the master agent listens at, or the subagent should connect to. The default is the Unix Domain socket "/var/agentx/master".  [String]  |
	| persistence_dir  | The directory to use to store persistence information. Change this if you want to use a custom snmpd instance, eg. for automatic testing.[String]  |

	- BIND_CONFIGURATION:
	
	| Key  | Value |
	| ------------- | ------------- |
	| host  | Host of bind API. [String]  |
	| port  | Port of bind API. [String]  |
	| stats_path  | Path to get statistics in bind.[String]  |

4. Install wheel in setup-package
	```
	pip install wheel-0.33.4-py2.py3-none-any.whl
	```
5. Install netsnmpagent and ipaddress in setup-package
	```
	pip install netsnmpagent-0.6.0.tar.gz
	pip install ipaddress-1.0.23-py2.py3-none-any.whl
	```
	- Note: If there is internet connection, install with requirements.txt in dns-snmp-agent:
		```
		pip install -r requirements.txt
		```
6.	Configure dns_stat_agent service
	- Copy service to /lib/systemd/system/
		```
		cp dns_stat_agent.service /lib/systemd/system/
		```
	- Set permission for dns_stat_agent.service
		```
		chmod -R 644 /lib/systemd/system/dns_stat_agent.service
		```
	- In dns_stat_agent.service file, need to change path of dns_stat_agent.py at ExecStart to where dns_stat_agent is stored.
	- Reload daemon and enable
		```
		systemctl daemon-reload
		systemctl enable dns_stat_agent.service
		```

### Run subagent
- Start dns_stat_agent service.
  ```
  service dns_stat_agent start
  ```
- Stop dns_stat_agent service.
  ```
  service dns_stat_agent stop
  ```
    
-	Note: Log files are stored at /var/log/dns_stat_agent/

## 3. Configuration Details
1. packetbeat.yml in /etc/packetbeat/
- Logging configuration is configured at Logging session in packetbeat.yml file.
- Configuring packetbeat capture packet at Transaction protocols session
	+ On type dns: it will be listen at ports: [53]
	+ On type http: it will be listen at ports: [51415], port 51415 (PORT) is SNMP Sub Agent Http port

2. statistics_config.json in /usr/share/packetbeat/bin/

| Key  | Value |  Description  |
| ------------- | ------------- | ------------- |
| statistics_destination  | http://[IP]:[PORT]/counter [String]  | IP and PORT of SNMP Sub Agent Http Server
| statistics_interval  | [integer]  | Interval collecting and sending DNS statistics
| maximum_clients  | [integer]  | maximum number of clients for statistics, 200 clients is required.
| url_announcement_bam_deploy  | "announcement-deploy-from-bam"  |  URL is called to Packetbeat HTTP server for updating ACL and matched clients for views from named config
| http_server_address  | [IP]:[PORT]  |  IP and PORT of Packetbeat HTTP Server to listen on announcement deployed from BAM.
| interval_clear_outstatis_cache  | [integer]  |  Interval In Second for cleaning data cached of data statistics which are sending to SNMP Agent


## 4. Get statistic data from mib
### Test to get statistic data
- Table
	```
	snmptable [OPTIONS] <IP> BCN-DNS-AGENT-MIB::<Statistic table name>
	```
- Walk
	```
	snmpwalk [OPTIONS] <IP> BCN-DNS-AGENT-MIB::<Object name>
	```
- Get
	```
	snmpget [OPTIONS] <IP> BCN-DNS-AGENT-MIB::<Object name>.\"<ClientIP/AsIP>\".<Metric type>
	```
 
### BAM ACLs Configuration
#### Create ACLs for Clients and Server
 
- The name of Client ACLs have to start with **_TrafficStatisticsAgent_Clients**
 Example:
    - _TrafficStatisticsAgent_Clients
    - _TrafficStatisticsAgent_Clients_Region_1
    - _TrafficStatisticsAgent_Clients_test
    
- The name of Client ACLs have to start with **_TrafficStatisticsAgent_Servers**
 Example:
    - _TrafficStatisticsAgent_Servers
    - _TrafficStatisticsAgent_Servers_Region_1
    - _TrafficStatisticsAgent_Servers_test
    
![ACLs](images/ACLs.PNG?raw=true)

- the ACL contains individual host IPs:
    - snmp agent create table entries with all statistics equal to zero
- the ACL contains only networks:
    - there are no SNMP OIDs be created.
