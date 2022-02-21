FROM ubuntu:20.04
ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install snmpd python curl software-properties-common -y && \
    rm -rf /var/lib/apt/lists/* && \
    apt-add-repository -y universe && \
    apt-get update && \
    curl https://bootstrap.pypa.io/pip/2.7/get-pip.py --output get-pip.py && \
    python get-pip.py

COPY . /opt/dns-snmp-agent/

# Install pip library
RUN pip install -r /opt/dns-snmp-agent/requirements.txt && \
    echo "mibs BCN-DNS-AGENT-MIB" > /etc/snmp/snmp.conf

CMD [ "/usr/bin/python", "/opt/dns-snmp-agent/dns_stat_agent.py" ]
