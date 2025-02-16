package com.acl.standard;

public class AclRule {
    private int aclNumber;
    private boolean isPermit;
    private String sourceIP;
    private String wildcard;

    public AclRule(String aclLine) {
        // Parse ACL line like: "access-list 3 deny 172.16.4.0 0.0.0.255"
        String[] parts = aclLine.split("\\s+");
        this.aclNumber = Integer.parseInt(parts[1]);
        this.isPermit = parts[2].equalsIgnoreCase("permit");
        this.sourceIP = parts[3];
        this.wildcard = parts.length > 4 ? parts[4] : "0.0.0.0";
    }

    public boolean matches(String ipAddress) {
        // Compare IP address with rule considering wildcard mask
        String[] sourceOctets = sourceIP.split("\\."); // e.g., "172.16.4.0" -> ["172", "16", "4", "0"]
        String[] wildcardOctets = wildcard.split("\\."); // e.g., "0.0.0.255" -> ["0", "0", "0", "255"]
        String[] ipOctets = ipAddress.split("\\."); // e.g., "172.16.4.5" -> ["172", "16", "4", "5"]

        for (int i = 0; i < 4; i++) {
            int source = Integer.parseInt(sourceOctets[i]);
            int wild = Integer.parseInt(wildcardOctets[i]);
            int ip = Integer.parseInt(ipOctets[i]);

            // If bits that must match (wild=0) don't match, return false
            if ((source & ~wild) != (ip & ~wild)) {
                return false;
            }
        }
        return true;
    }

    public boolean isPermit() {
        return isPermit;
    }

    public int getAclNumber() {
        return aclNumber;
    }

}