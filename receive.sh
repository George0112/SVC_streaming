#!/bin/bash

cd ../customed_svef
pwd
rm -f receivedtrace.txt
./receiver 4455 out.264 10000 > receivedtrace.txt
sleep 2

sh play.sh

