#!/bin/bash
echo "Update dns-traffic-statistics-agent binaries"
dns_traffic_dir=$PWD

echo $dns_traffic_dir

echo "Stop dns-snmp-agent service"
systemctl stop dns_stat_agent

if [ -d "/opt/dns-snmp-agent/" ]; then
    echo "Backup /opt/dns-snmp-agent to $dns_traffic_dir/dns-traffic-statistics-agent/backup/"
    mkdir -p $dns_traffic_dir/backup/opt/
    cp -rf /opt/dns-snmp-agent/ $dns_traffic_dir/backup/opt/
fi

echo "Stop packetbeat service"
systemctl stop packetbeat
if [ -d "/usr/share/packetbeat/" ]; then
    echo "Backup /usr/share/packetbeat/ to $dns_traffic_dir/dns-traffic-statistics-agent/backup/"
    mkdir -p $dns_traffic_dir/backup/usr/share/packetbeat/
    cp -rf /usr/share/packetbeat/bin/packetbeat $dns_traffic_dir/backup/usr/share/packetbeat/
fi

echo "Apply packetbeat binaries"
rm -rf /usr/share/packetbeat/bin/packetbeat
cp -rf $dns_traffic_dir/packetbeat/packetbeat /usr/share/packetbeat/bin/

echo "Apply new dns-snmp-agent binaries"
rm -rf /opt/dns-snmp-agent/
cp -rf $dns_traffic_dir/dns-snmp-agent/ /opt/

echo "Start dns-snmp-agent service"
systemctl start dns_stat_agent

echo "Start packetbeat service"
systemctl start packetbeat

echo "END"
exec bash -i
