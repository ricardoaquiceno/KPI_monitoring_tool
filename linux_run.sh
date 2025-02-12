#!/bin/bash
sudo setcap cap_net_raw,cap_net_admin=eip bin/go_build_test
./bin/go_build_test