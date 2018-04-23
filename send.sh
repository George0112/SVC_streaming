#!/bin/bash

cd ../customed_svef/$1
./streamer CREW52trace-rdo.txt 30 $2 4455 CREW52.264 > sent.txt
