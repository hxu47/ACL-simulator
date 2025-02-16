package com.acl.extended;

import com.acl.standard.StandardACL;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class ExtendedACL {
    List<ExtendedAclRule> rules;
    private boolean isInbound;
    private int aclNumber;

    public ExtendedACL() {
        // Initialize an empty list to store Extended ACL rules.
        this.rules = new ArrayList<>();
    }

    public void loadRules(String filename) throws IOException {
        try (BufferedReader reader = new BufferedReader(new FileReader(filename))) {
            String line;
            while ((line = reader.readLine()) != null) {
                line = line.trim();
                if (line.startsWith("access-list")) {
                    // Create new AclRule from the line and add to rules list
                    rules.add(new ExtendedAclRule(line));
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
                String[] parts = line.trim().split("\\s+");
                String sourceIP = parts[0];
                String destIP = parts[1];
                Integer port = parts.length > 2 ? Integer.parseInt(parts[2]) : null;
                boolean packetProcessed = false;

                // Try each rule until a match is found
                for (ExtendedAclRule rule : rules) {
                    if (rule.getAclNumber() == this.aclNumber && rule.matches(sourceIP, destIP, port)) {
                        System.out.println("Packet from " + sourceIP + " to " + destIP
                                + (port == null ? "" : " on port " + port)
                                + (rule.isPermit() ? " permitted" : " denied"));
                        packetProcessed = true;
                        break;
                    }
                }

                // If no rule matched, apply implicit deny
                if (!packetProcessed) {
                    System.out.println("Packet from " + sourceIP + " to " + destIP
                            + (port == null ? "" : " on port " + port)
                            + " denied");
                }
            }
        }
    }


    public static void main(String[] args) {
        ExtendedACL acl = new ExtendedACL();
        try {

            // Update these paths according to your project structure
            acl.loadRules("input/extended/acl.txt");
            for (ExtendedAclRule rule : acl.rules) {
                System.out.println(rule.getAclNumber());
                System.out.println(rule.isPermit());
                System.out.println(rule.getProtocol());
                System.out.println(rule.sourceIP);
                System.out.println(rule.sourceWildcard);
                System.out.println(rule.destIP);
                System.out.println(rule.destWildcard);
                System.out.println("=========");
            }

            acl.processPackets("input/standard/packets1.txt");
        } catch (IOException e) {
            System.err.println("Error processing files: " + e.getMessage());
        }
    }



}
