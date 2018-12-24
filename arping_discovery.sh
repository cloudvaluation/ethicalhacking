#!/bin/bash

if ["$#" -ne 1]; then
echo "Usage - ./arping_discovery.sh [interface]"
echo "Example: ./arping_discovery.sh eth0"
exit
fi

interface=$1
prefix=$(ifconfig $interface | grep 'inet ' | cut -d '	' -f 1 | cut -d 'n' -f 2 | cut ' '-f 2)

for addr in $(sep 100 110); do
arping -c 1 $prfix.$addr | grep "bytes from" | cut -d " " -f 5 | cut -d "(" -f 2 | cut -d ")" -f 1 &
done

