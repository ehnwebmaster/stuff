#!/bin/bash
sleep 2
count=0
while true ; do
        sleep 2
        if ping -c1 -w1 1.1.1.1 >/dev/null 2>&1 ; then
                count=0
                echo "internet Ok"
        else
                count=$((count + 1))
                if [ $count -gt 3 ]; then
                        count=0
                        #service restart_wan
                        echo "Internet faiL"
                fi
        fi
done
