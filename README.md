# ACL Simulator

This application simulates the processing of Access Control Lists (ACLs) at a router's interface. It supports both Standard and Extended ACLs.

## Table of Contents
- [Prerequisites](#prerequisites)
- [Building the Application](#building-the-application)
- [Running the Application](#running-the-application)
    - [Using Shell Scripts](#using-shell-scripts-recommended)
    - [Alternative Method](#alternative-method-using-java-directly)
- [Input File Format](#input-file-format)
    - [Standard ACL](#standard-acl)
    - [Extended ACL](#extended-acl)
- [Sample Files](#sample-files)
- [Testing](#testing)


## Prerequisites

- Java 17 or higher
- Maven

## Building the Application

1. Clone the repository:
```bash
git clone https://github.com/hxu47/ACL-simulator.git
cd acl-simulator
```

2. Build the project using Maven:
```bash
mvn clean package
```

This will create two JAR files in the `target` directory:
- `acl-simulator-1.0-SNAPSHOT-standard.jar` - for Standard ACL simulation
- `acl-simulator-1.0-SNAPSHOT-extended.jar` - for Extended ACL simulation

## Running the Application

### Using Shell Scripts (Recommended)

1. Make the shell scripts executable:
```bash
chmod +x standard-acl.sh extended-acl.sh
```

2. Run Standard ACL Simulator:
```bash
./standard-acl.sh <acl-file> <packets-file>
```
Example:
```bash
./standard-acl.sh input/standard/acl1.txt input/standard/packets1.txt
```

3. Run Extended ACL Simulator:
```bash
./extended-acl.sh <acl-file> <packets-file>
```
Example:
```bash
./extended-acl.sh input/extended/acl1.txt input/extended/packets1.txt
```

### Alternative Method (Using Java directly)

You can also run the simulators directly using the Java command:

For Standard ACL:
```bash
java -jar target/acl-simulator-1.0-SNAPSHOT-standard.jar <acl-file> <packets-file>
```

For Extended ACL:
```bash
java -jar target/acl-simulator-1.0-SNAPSHOT-extended.jar <acl-file> <packets-file>
```

## Input File Format

### Standard ACL

1. ACL Rules file format:
```
access-list <number> <permit|deny> <source-ip> <wildcard>
interface <interface-name>
ip access-group <number> <in|out>
```
Example:
```
access-list 3 deny 172.16.4.0 0.0.0.255
access-list 3 permit 172.16.0.0 0.0.255.255
interface E0
ip access-group 3 out
```

2. Packets file format:
```
<source-ip>
```
Example:
```
172.16.4.1
172.16.3.5
201.15.3.4
```

### Extended ACL

1. ACL Rules file format:
```
access-list <number> <permit|deny> <protocol> <source-ip> <wildcard> <dest-ip> <wildcard> [eq <port>|range <port-range>]
interface <interface-name>
ip access-group <number> <in|out>
```
Example:
```
access-list 101 deny tcp any 192.168.1.100 0.0.0.0 eq 80
access-list 101 permit tcp 172.16.0.0 0.0.255.255 any eq 80
access-list 101 permit tcp any any eq 443
interface E0
ip access-group 101 out
```

2. Packets file format:
```
<source-ip> <dest-ip> <port>
```
Example:
```
172.16.4.4 172.16.3.1 20
172.16.4.4 172.16.3.5 22
172.25.3.1 172.16.3.4 22
```

## Sample Files

Sample input files are provided in the `input` directory:
- Standard ACL examples: `input/standard/`
- Extended ACL examples: `input/extended/`

## Testing

Run the test suite using Maven:
```bash
mvn test
```
