package com.acl.standard;

import java.io.IOException;

public class StandardACLSimulator {
    public static void main(String[] args) {
        if (args.length != 2) {
            System.out.println("Usage: java StandardACLSimulator <acl-file> <packets-file>");
            System.exit(1);
        }

        String aclFile = args[0];
        String packetsFile = args[1];

        StandardACL acl = new StandardACL();
        try {
            acl.loadRules(aclFile);
            acl.processPackets(packetsFile);
        } catch (IOException e) {
            System.err.println("Error processing files: " + e.getMessage());
            System.exit(1);
        }
    }
}