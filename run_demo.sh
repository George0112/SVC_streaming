#!/bin/bash

THIS_DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

source env.sh

#P4C_BM_SCRIPT=$P4C_BM_PATH/p4c_bm/__main__.py

SWITCH_PATH=$BMV2_PATH/targets/simple_switch/simple_switch

CLI_PATH=$BMV2_PATH/tools/runtime_CLI.py
#CLI_PATH=$BMV2_PATH/targets/simple_switch/simple_switch_CLI

#$P4C_BM_SCRIPT p4src/source_routing.p4 --json source_routing.json
p4c-bm2-ss --arch v1model -o demo.json \
		--p4runtime-file mytunnel.p4info --p4runtime-format text \
		p4src/task1.p4

# This gives libtool the opportunity to "warm-up"
sudo $SWITCH_PATH >/dev/null 2>&1
sudo PYTHONPATH=$PYTHONPATH:$BMV2_PATH/mininet/ python topo.py \
    --behavioral-exe simple_switch \
    --json demo.json \
    --cli $CLI_PATH
