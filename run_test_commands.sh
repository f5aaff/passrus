#!/bin/bash

if [ -z "$1" ] || [ -z "$(cat "$1")" ]; then
    printf "\n\e[1;31m provide a path to a valid command .json file.\n \e[m"
    exit 1
fi

cat $1 | socat - UNIX-CONNECT:/tmp/passman.sock
