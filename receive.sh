#!/bin/bash

cd ../customed_svef/$1
pwd
rm -f receivedtrace.txt
./receiver 4455 out.264 10000 > receivedtrace.txt
sleep 2

sh play.sh CREW52 $1

