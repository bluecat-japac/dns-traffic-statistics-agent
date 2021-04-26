FROM ubuntu:16.04

RUN apt-get update && \
    apt-get install snmpd python-pip -y 

COPY . /opt/dns-snmp-agent/

# Install pip library
RUN pip install -r /opt/dns-snmp-agent/requirements.txt && \
    echo "mibs BCN-DNS-AGENT-MIB" > /etc/snmp/snmp.conf

CMD [ "/usr/bin/python", "/opt/dns-snmp-agent/dns_stat_agent.py" ]
