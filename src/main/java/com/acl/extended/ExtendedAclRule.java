package com.acl.extended;

import java.util.Set;
import java.util.HashSet;

public class ExtendedAclRule {
    private static final Set<String> PORTLESS_PROTOCOLS = new HashSet<String>() {{
        add("ip");
        add("icmp");
        add("igmp");
    }};

    private int aclNumber;
    private boolean isPermit;
    private String protocol;
    String sourceIP;
    String sourceWildcard;
    String destIP;
    String destWildcard;
    private Integer portRangeStart;
    private Integer portRangeEnd;
    private boolean isPortRange;

    public ExtendedAclRule(String aclLine) {
        String[] parts = aclLine.split("\\s+");
        this.aclNumber = Integer.parseInt(parts[1]);
        this.isPermit = parts[2].equalsIgnoreCase("permit");
        this.protocol = parts[3].toLowerCase();

        int currentIndex = 4;  // Start after protocol

        // Parse source IP and wildcard
        if (parts[currentIndex].equalsIgnoreCase("any")) {
            this.sourceIP = "0.0.0.0";
            this.sourceWildcard = "255.255.255.255";
            currentIndex++;
        } else {
            this.sourceIP = parts[currentIndex++];
            this.sourceWildcard = parts[currentIndex++];
        }

        // Parse destination IP and wildcard
        if (parts[currentIndex].equalsIgnoreCase("any")) {
            this.destIP = "0.0.0.0";
            this.destWildcard = "255.255.255.255";
            currentIndex++;
        } else {
            this.destIP = parts[currentIndex++];
            this.destWildcard = parts[currentIndex++];
        }

        // Parse port specifications if present and protocol uses ports
        if (!PORTLESS_PROTOCOLS.contains(protocol) && currentIndex < parts.length) {
            parsePortSpecification(parts[currentIndex], parts[currentIndex + 1]);
        }
    }

    private void parsePortSpecification(String portType, String portValue) {
        if (portType.equals("range")) {
            // Handle port range (e.g., "range 20-21")
            String[] portRange = portValue.split("-");
            this.isPortRange = true;
            this.portRangeStart = Integer.parseInt(portRange[0]);
            this.portRangeEnd = Integer.parseInt(portRange[1]);
        } else if (portType.equals("eq")) {
            // Handle single port (e.g., "eq 80")
            this.isPortRange = false;
            this.portRangeStart = Integer.parseInt(portValue);
            this.portRangeEnd = this.portRangeStart;
        }
    }

    private boolean ipMatches(String ip, String ruleIP, String wildcard) {
        String[] ipOctets = ip.split("\\.");
        String[] ruleOctets = ruleIP.split("\\.");
        String[] wildcardOctets = wildcard.split("\\.");

        for (int i = 0; i < 4; i++) {
            int ipOctet = Integer.parseInt(ipOctets[i]);
            int ruleOctet = Integer.parseInt(ruleOctets[i]);
            int wildcardOctet = Integer.parseInt(wildcardOctets[i]);

            if ((ruleOctet & ~wildcardOctet) != (ipOctet & ~wildcardOctet)) {
                return false;
            }
        }
        return true;
    }

    private boolean portMatches(Integer port) {
        // If packet doesn't specify port, only match if rule doesn't specify port
        if (port == null) {
            return portRangeStart == null;
        }

        // If no port specification in rule, match any port
        if (portRangeStart == null) {
            return true;
        }

        if (isPortRange) {
            return port >= portRangeStart && port <= portRangeEnd;
        } else {
            return port.equals(portRangeStart);
        }
    }


    public boolean matches(String sourceIP, String destIP, Integer port) {
        // Check if IPs match
        boolean sourceMatches = ipMatches(sourceIP, this.sourceIP, this.sourceWildcard);
        boolean destMatches = ipMatches(destIP, this.destIP, this.destWildcard);
        boolean portMatches = portMatches(port);

        // For protocols without ports, ignore port matching
        if (PORTLESS_PROTOCOLS.contains(protocol)) {
            return sourceMatches && destMatches;
        }

        // For protocols with ports, check all conditions
        return sourceMatches && destMatches && portMatches;
    }

    public boolean isPermit() {
        return isPermit;
    }

    public int getAclNumber() {
        return aclNumber;
    }

    public String getProtocol() {
        return protocol;
    }
}