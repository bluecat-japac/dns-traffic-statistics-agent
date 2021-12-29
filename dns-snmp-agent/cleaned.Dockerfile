# Support remove "cpp" and "mirror" in container
ARG IMAGE=dns_stat_agent:<tag>
FROM $IMAGE
RUN   ln -s / /rootlink && \
      rm -rf /usr/lib/apt/methods/mirror* \
            /etc/alternatives/cpp \
            /usr/bin/cpp \
            /usr/lib/cpp  \
            /lib/cpp \
            /usr/share/doc/cpp \
            /var/lib/dpkg/alternatives/cpp
FROM scratch
COPY --from=0 /rootlink/ /
RUN rm -rf /rootlink
CMD [ "/usr/bin/python", "/opt/dns-snmp-agent/dns_stat_agent.py" ]