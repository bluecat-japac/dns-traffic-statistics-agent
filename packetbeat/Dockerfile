FROM ubuntu:16.04

RUN apt-get update && \
    mkdir -p /usr/share/packetbeat && \
    mkdir -p /usr/share/packetbeat/bin && \
    mkdir -p /etc/packetbeat

COPY statistics_config.json announcement_bam_deploy.py bin/packetbeat /usr/share/packetbeat/bin/
COPY packetbeat.yml /etc/packetbeat/

CMD ["/usr/share/packetbeat/bin/packetbeat", "-c", "/etc/packetbeat/packetbeat.yml", "--path.logs", "/var/log/packetbeat", "--path.home", "/usr/share/packetbeat", "--path.config", "/etc/packetbeat", "--path.data", "/var/lib/packetbeat"]
