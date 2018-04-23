#!/bin/bash

cd ../customed_svef/$1
./streamer ICE52trace-rdo.txt 30 $2 4456 ICE52.264 > sent.txt
