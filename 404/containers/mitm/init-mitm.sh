#!/bin/sh

set -e
mitmdump --set block_global=false --set keep_host_header=true --mode reverse:http://${PROXY_ADDRESS}:${PROXY_PORT} -p ${MITM_PORT} -s ./load_mitm.py