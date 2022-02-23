#!/bin/bash

set -ex

useradd -u $(stat -c %u /build) xdpbuilder
sudo rm -rf /build/out

cd /build/module
sudo -u xdpbuilder make clean
sudo -u xdpbuilder make
cd /build/loader
sudo -u xdpbuilder make

mkdir -p /build/out/module /build/out/rule_generator
cp /build/module/*.o /build/out/module
cp /build/module/xdp-mfw /build/out/module
cp /build/module/xdp_loader /build/out/module
cp /build/testenv/gen-rule.py /build/out/rule_generator

cd /build/out

sleep 1
sudo -u xdpbuilder tar zcvf ../release.tar.gz ./ --owner=0 --group=0
sleep 1