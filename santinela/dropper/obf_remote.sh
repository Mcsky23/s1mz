#!/bin/bash

ip=$1
scp dropper/specter.py $ip:/tmp
scp dropper/dropper.py $ip:/tmp
ssh $ip "python3 /tmp/specter.py"
scp $ip:/tmp/obf-dropper.py dropper/obf-dropper.py
ssh $ip "rm /tmp/specter.py /tmp/dropper.py /tmp/obf-dropper.py"