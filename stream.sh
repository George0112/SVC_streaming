#!/bin/bash

echo 'streaming'

../customed_svef/streamer ../customed_svef/originaltrace-rdo.txt 30 10.0.0.1 4455 > sent.txt