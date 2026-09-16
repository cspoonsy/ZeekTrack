#!/bin/bash

# Used to replay simulated noise to the switch

while true; do
    tcpreplay -i eth0 scripts/noise-scripts/lan_noise.pcap
    sleep 20
done