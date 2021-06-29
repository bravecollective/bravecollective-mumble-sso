#!/bin/bash

while true; do
    python -u mumble-sso-auth.py 2>&1 | tee -a mumble-sso-auth.log
    sleep 5
done
