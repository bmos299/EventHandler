#!/bin/bash
mkdir -p ./depends
pushd ./depends
# fetch libsnark
git clone https://github.com/scipr-lab/libsnark.git --recursive
pushd ./libsnark
git checkout 2af440246fa2c3d0b1b0a425fb6abd8cc8b9c54d
popd
# fetch yaml-cpp
git clone https://github.com/jbeder/yaml-cpp.git
pushd ./yaml-cpp
git checkout 98acc5a8874faab28b82c28936f4b400b389f5d6
popd
# fetch rapidcsv
git clone https://github.com/d99kris/rapidcsv.git
pushd ./rapidcsv
git checkout d3b440b00304e9ac8d6c0d404649be33840c6249
popd
# fetch lemon
wget http://lemon.cs.elte.hu/pub/sources/lemon-1.3.1.tar.gz
tar -zxvf lemon-1.3.1.tar.gz
popd
