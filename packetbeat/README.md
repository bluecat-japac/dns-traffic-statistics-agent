
# Packetbeat

Packetbeat is an open source network packet analyzer that ships the data to
Elasticsearch. Think of it like a distributed real-time Wireshark with a lot
more analytics features.

The Packetbeat shippers sniff the traffic between your application processes,
parse on the fly protocols like HTTP, MySQL, PostgreSQL, Redis or Thrift and
correlate the messages into transactions.

For each transaction, the shipper inserts a JSON document into Elasticsearch,
where it is stored and indexed. You can then use Kibana to view key metrics and
do ad-hoc queries against the data.

To learn more about Packetbeat, check out <https://www.elastic.co/products/beats/packetbeat>.

## Getting started

Please follow the [getting started](https://www.elastic.co/guide/en/beats/packetbeat/current/packetbeat-getting-started.html)
guide from the docs.

## Documentation

Please visit
[elastic.co](https://www.elastic.co/guide/en/beats/packetbeat/current/index.html) for the
documentation.

## Bugs and feature requests

If you have an issue, please start by opening a topic on the
[forums](https://discuss.elastic.co/c/beats/packetbeat). We'll help you
troubleshoot and work with you on a solution.

If you are sure you found a bug or have a feature request, open an issue on
[Github](https://github.com/elastic/beats/issues).

## Contributions

We love contributions from our community! Please read the
[CONTRIBUTING.md](../CONTRIBUTING.md) file.

## Snapshots

For testing purposes, we generate snapshot builds that you can find [here](https://beats-nightlies.s3.amazonaws.com/index.html?prefix=packetbeat). Please be aware that these are built on top of master and are not meant for production.

<!-- BlueCat Networks -->
## Packaging .deb
1. Unpackaging $PACKETBEAT-OldVer.deb
    1. Create $PACKETBEAT_DIR directory
    2. Run cmd:
        ```
        dpkg-deb -R $PACKETBEAT-OLD.deb $PACKETBEAT_DIR
        ```
2. Configure and packaging
    1. Configuration
        - Change package's information at $PACKETBEAT_DIR/DEBIAN/control
        (Note: "Package" which in this file will be $PACKETBEAT-NAME)
        - Set permission for file which installed at $PACKETBEAT_DIR/DEBIAN/postinst
    2. Update new file
        - Remove old and copy new "packetbeat.yml" at $PACKETBEAT_DIR/etc/packetbeat/
        - Remove old and copy new "packetbeat" binary, "statistics_config.json", "announcement_bam_deploy.py" at $PACKETBEAT_DIR/usr/share/packetbeat/bin/
    3. Packaging
        ```
        dpkg-deb -b $PACKETBEAT_DIR $PACKETBEAT-NewVer.deb  
        ```

## Install and uninstall
1.  Install
    ```
	dpkg -i $PACKETBEAT-NewVer.deb
    ```		
2.  Remove
    ```
	dpkg -P $PACKETBEAT-NAME
    ```
<!-- BlueCat Networks End-->