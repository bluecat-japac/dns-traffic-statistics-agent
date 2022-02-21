FROM ubuntu:20.04

RUN apt-add-repository -y universe && \
    apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install snmpd python curl software-properties-common -y && \
    curl https://bootstrap.pypa.io/pip/2.7/get-pip.py --output get-pip.py && \
    python get-pip.py && \
    rm -rf /var/lib/apt/lists/*

COPY . /opt/dns-snmp-agent/

# Install pip library
RUN pip install -r /opt/dns-snmp-agent/requirements.txt && \
    echo "mibs BCN-DNS-AGENT-MIB" > /etc/snmp/snmp.conf

CMD [ "/usr/bin/python", "/opt/dns-snmp-agent/dns_stat_agent.py" ]
