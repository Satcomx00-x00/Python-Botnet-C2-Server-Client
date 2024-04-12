#!/bin/bash
# apt update
apt-get install tor -y
service tor start
apt-get install build-essential libssl-dev libffi-dev python-dev -y
apt install inspircd -y
nano /etc/inspircd/inspircd.conf