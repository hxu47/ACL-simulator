package com.acl.standard;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class StandardACL {
    public List<AclRule> rules;
    private boolean isInbound;
    private int aclNumber;

    public StandardACL() {
        // Initialize an empty list to store ACL rules.
        this.rules = new ArrayList<>();
    }

    public void loadRules(String filename) throws IOException {
        try (BufferedReader reader = new BufferedReader(new FileReader(filename))) {
            String line;
            while ((line = reader.readLine()) != null) {
                line = line.trim();
                if (line.startsWith("access-list")) {
                    // Create new AclRule from the line and add to rules list
                    rules.add(new AclRule(line));
                } else if (line.startsWith("interface")) {
                    // Skip interface line (e.g., "interface E0")
                    continue;
                } else if (line.startsWith("ip access-group")) {
                    // Parse line like "ip access-group 3 out"
                    String[] parts = line.split("\\s+");
                    this.aclNumber = Integer.parseInt(parts[2]);  // Get ACL number
                    this.isInbound = parts[3].equals("in");      // Check if inbound
                }
            }
        }
    }

    public void processPackets(String filename) throws IOException {
        try (BufferedReader reader = new BufferedReader(new FileReader(filename))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String sourceIP = line.trim();
                boolean packetProcessed = false;

                // Try each rule until a match is found
                for (AclRule rule : rules) {
                    if (rule.getAclNumber() == this.aclNumber && rule.matches(sourceIP)) {
                        System.out.println("Packet from " + sourceIP + " " +
                                (rule.isPermit() ? "permitted" : "denied"));
                        packetProcessed = true;
                        break;
                    }
                }

                // If no rule matched, apply implicit deny
                if (!packetProcessed) {
                    System.out.println("Packet from " + sourceIP + " denied");
                }
            }
        }
    }

    public static void main(String[] args) {
        StandardACL acl = new StandardACL();
        try {
            // Update these paths according to your project structure
            acl.loadRules("input/standard/acl1.txt");
//            for (AclRule rule : acl.rules) {
//                System.out.println(rule.getAclNumber());
//                System.out.println(rule.isPermit());
//            }
//            System.out.println(acl.aclNumber);
//            System.out.println(acl.isInbound);

            acl.processPackets("input/standard/packets1.txt");
        } catch (IOException e) {
            System.err.println("Error processing files: " + e.getMessage());
        }
    }
}
