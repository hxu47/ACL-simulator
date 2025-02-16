package com.acl.standard;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

public class StandardACLTest {
    private StandardACL acl;
    private final ByteArrayOutputStream outContent = new ByteArrayOutputStream();
    private final PrintStream originalOut = System.out;

    @TempDir
    Path tempDir;

    @BeforeEach
    void setUp() {
        acl = new StandardACL();
        // Redirect System.out to capture output
        System.setOut(new PrintStream(outContent));
    }

    @Test
    void testBasicACLRules() throws IOException {
        // Create temporary ACL rules file
        Path aclFile = tempDir.resolve("acl1.txt");
        String aclContent = String.join("\n",
                "access-list 3 deny 172.16.4.0 0.0.0.255",
                "access-list 3 permit 172.16.0.0 0.0.255.255",
                "interface E0",
                "ip access-group 3 out");
        Files.writeString(aclFile, aclContent);

        // Create temporary packets file
        Path packetsFile = tempDir.resolve("packets1.txt");
        String packetsContent = String.join("\n",
                "172.16.4.1",
                "172.16.3.5",
                "201.15.3.4");
        Files.writeString(packetsFile, packetsContent);

        // Process the files
        acl.loadRules(aclFile.toString());
        acl.processPackets(packetsFile.toString());

        // Get output and normalize line endings
        String output = outContent.toString().replace("\r\n", "\n");

        // Verify expected output
        String expectedOutput = String.join("\n",
                "Packet from 172.16.4.1 denied",
                "Packet from 172.16.3.5 permitted",
                "Packet from 201.15.3.4 denied",
                "");

        assertEquals(expectedOutput, output);
    }

    @Test
    void testImplicitDeny() throws IOException {
        // Create temporary ACL rules file
        Path aclFile = tempDir.resolve("acl1.txt");
        String aclContent = String.join("\n",
                "access-list 1 permit 192.168.1.0 0.0.0.255",
                "interface E0",
                "ip access-group 1 out");
        Files.writeString(aclFile, aclContent);

        // Create temporary packets file
        Path packetsFile = tempDir.resolve("packets1.txt");
        String packetsContent = String.join("\n",
                "172.16.1.1",
                "10.0.0.1");
        Files.writeString(packetsFile, packetsContent);

        acl.loadRules(aclFile.toString());
        acl.processPackets(packetsFile.toString());

        String output = outContent.toString().replace("\r\n", "\n");
        String expectedOutput = String.join("\n",
                "Packet from 172.16.1.1 denied",
                "Packet from 10.0.0.1 denied",
                "");

        assertEquals(expectedOutput, output);
    }

    @Test
    void testFileNotFound() {
        Exception exception = assertThrows(IOException.class, () -> {
            acl.loadRules("nonexistent.txt");
        });
        assertTrue(exception.getMessage().contains("nonexistent.txt"));
    }

    @Test
    void testEmptyACLFile() throws IOException {
        Path aclFile = tempDir.resolve("empty.txt");
        Files.writeString(aclFile, "");

        Path packetsFile = tempDir.resolve("packets1.txt");
        Files.writeString(packetsFile, "192.168.1.1");

        acl.loadRules(aclFile.toString());
        acl.processPackets(packetsFile.toString());

        String output = outContent.toString().replace("\r\n", "\n");
        String expectedOutput = "Packet from 192.168.1.1 denied\n";

        assertEquals(expectedOutput, output);
    }
}