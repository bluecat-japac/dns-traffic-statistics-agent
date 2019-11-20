# SNMP SUBAGENT OF DNS TRAFFIC STATISTIC

### Desscription
- Provide DNS traffic statistics to a Network Monitoring System via SNMP.
- Subagent will receive statistics data after interval time from packetbeat via REST API, and then store into the already defined mib.

------------


### CONFIGUARATION 
- Copy **BCN-DNS-AGENT-MIB.mib** into folder /usr/share/snmp/mibs.
- Append "BCN-DNS-AGENT-MIB" end of /etc/snmp/snmp.conf.

------------

### Run
1. Navigate to **dns-snmp-agent** folder.
2. Run

    ```
    nohup python dns_stat_agent.py &
    ```
3. Get
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

------------
