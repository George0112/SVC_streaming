#!/bin/bash

cd ../customed_svef
./receiver 4455 out.264 10000 > receivedtrace.txt
sleep 2
python demo.py &


sh play.sh

python pltpsnr.py &
