# Support remove "cpp" and "mirror" in container
ARG IMAGE=dns_packetbeat:<tag>
FROM $IMAGE
RUN   ln -s / /rootlink && \
      rm -rf /usr/lib/apt/methods/mirror*
      
FROM scratch
COPY --from=0 /rootlink/ /
RUN rm -rf /rootlink
CMD ["/usr/share/packetbeat/bin/packetbeat", "-c", "/etc/packetbeat/packetbeat.yml", "--path.logs", "/var/log/packetbeat", "--path.home", "/usr/share/packetbeat", "--path.config", "/etc/packetbeat", "--path.data", "/var/lib/packetbeat"]
