package com.acl.extended;

public class ExtendedAclRule {
    private int aclNumber;
    private boolean isPermit;
    private String protocol;
    private String sourceIP;
    private String sourceWildcard;
    private String destIP;
    private String destWildcard;
    private Integer portRangeStart;
    private Integer portRangeEnd;
    private boolean isPortRange;

    public ExtendedAclRule(String aclLine) {
        // Parse ACL line like:
        // "access-list 101 deny tcp 172.16.0.0 0.0.255.255 172.16.3.0 0.0.0.255 range 20-21"
        // or "access-list 101 deny tcp 172.16.0.0 0.0.255.255 172.16.3.0 0.0.0.255 eq 80"
        String[] parts = aclLine.split("\\s+");
        this.aclNumber = Integer.parseInt(parts[1]);
        this.isPermit = parts[2].equalsIgnoreCase("permit");
        this.protocol = parts[3];
        this.sourceIP = parts[4];
        this.sourceWildcard = parts[5];
        this.destIP = parts[6];
        this.destWildcard = parts[7];

        // Handle port specifications if present
        if (parts.length > 8) {
            if (parts[8].equals("range")) {
                // Handle port range (e.g., "range 20-21")
                this.isPortRange = true;
                String[] portRange = parts[9].split("-");
                this.portRangeStart = Integer.parseInt(portRange[0]);
                this.portRangeEnd = Integer.parseInt(portRange[1]);
            } else if (parts[8].equals("eq")) {
                // Handle single port (e.g., "eq 80")
                this.isPortRange = false;
                this.portRangeStart = Integer.parseInt(parts[9]);
                this.portRangeEnd = this.portRangeStart;
            }
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

    public boolean matches(String sourceIP, String destIP, int port) {
        // Check if IPs match
        boolean sourceMatches = ipMatches(sourceIP, this.sourceIP, this.sourceWildcard);
        boolean destMatches = ipMatches(destIP, this.destIP, this.destWildcard);

        // If port is specified, check if port matches
        boolean portMatches = true;
        if (portRangeStart != null) {
            if (isPortRange) {
                portMatches = port >= portRangeStart && port <= portRangeEnd;
            } else {
                portMatches = port == portRangeStart;
            }
        }

        return sourceMatches && destMatches && portMatches;
    }

    public boolean isPermit() {
        return isPermit;
    }

    public int getAclNumber() {
        return aclNumber;
    }
}