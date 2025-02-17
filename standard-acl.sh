#!/bin/bash

# Make this script executable
chmod +x "${0}"

# Check if two arguments are provided
if [ $# -ne 2 ]; then
    echo "Usage: ./standard-acl.sh <acl-file> <packets-file>"
    echo "Example: ./standard-acl.sh input/standard/acl1.txt input/standard/packets1.txt"
    exit 1
fi

# Run the standard ACL simulator
java -jar target/acl-simulator-1.0-SNAPSHOT-standard.jar "$1" "$2"