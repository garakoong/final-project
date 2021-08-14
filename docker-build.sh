#!/bin/bash

set -ex

useradd -u $(stat -c %u /build) xdpbuilder

cd /build/module
sudo -u xdpbuilder make clean
sudo -u xdpbuilder make
cd /build/loader
sudo -u xdpbuilder make