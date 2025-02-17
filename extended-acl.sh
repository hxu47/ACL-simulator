#!/bin/bash

# Make this script executable
chmod +x "${0}"

# Check if two arguments are provided
if [ $# -ne 2 ]; then
    echo "Usage: ./extended-acl.sh <acl-file> <packets-file>"
    echo "Example: ./extended-acl.sh input/extended/acl1.txt input/extended/packets1.txt"
    exit 1
fi

# Run the extended ACL simulator
java -jar target/acl-simulator-1.0-SNAPSHOT-extended.jar "$1" "$2"