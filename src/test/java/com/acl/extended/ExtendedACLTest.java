package com.acl.extended;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

public class ExtendedACLTest {
    private ExtendedACL acl;
    private final ByteArrayOutputStream outContent = new ByteArrayOutputStream();
    private final PrintStream originalOut = System.out;

    @TempDir
    Path tempDir;

    @BeforeEach
    void setUp() {
        acl = new ExtendedACL();
        System.setOut(new PrintStream(outContent));
    }

    @Test
    void testWebServerAccessControl() throws IOException {
        // Create temporary ACL rules file
        Path aclFile = tempDir.resolve("acl.txt");
        String aclContent = String.join("\n",
                "access-list 101 deny tcp any 192.168.1.100 0.0.0.0 eq 80",
                "access-list 101 permit tcp 172.16.0.0 0.0.255.255 any eq 80",
                "access-list 101 permit tcp any any eq 443",
                "interface E0",
                "ip access-group 101 out");
        Files.writeString(aclFile, aclContent);

        // Create temporary packets file
        Path packetsFile = tempDir.resolve("packets.txt");
        String packetsContent = String.join("\n",
                "10.1.1.1 192.168.1.100 80",    // Should be denied by first rule
                "172.16.1.1 192.168.1.100 80",  // Should be denied by first rule
                "172.16.1.1 10.0.0.1 80",       // Should be permitted by second rule
                "192.168.1.1 172.16.1.1 443",   // Should be permitted by third rule
                "172.16.1.1 192.168.1.100 443"); // Should be permitted by third rule
        Files.writeString(packetsFile, packetsContent);

        // Process the files
        acl.loadRules(aclFile.toString());
        acl.processPackets(packetsFile.toString());


        // Get output and normalize line endings
        String output = outContent.toString().replace("\r\n", "\n");

        // Verify expected output
        String expectedOutput = String.join("\n",
                "Packet from 10.1.1.1 to 192.168.1.100 on port 80 denied",
                "Packet from 172.16.1.1 to 192.168.1.100 on port 80 denied",
                "Packet from 172.16.1.1 to 10.0.0.1 on port 80 permitted",
                "Packet from 192.168.1.1 to 172.16.1.1 on port 443 permitted",
                "Packet from 172.16.1.1 to 192.168.1.100 on port 443 permitted",
                "");

        assertEquals(expectedOutput, output);
    }

    @Test
    void testMixedProtocols() throws IOException {
        Path aclFile = tempDir.resolve("acl.txt");
        String aclContent = String.join("\n",
                "access-list 102 deny tcp 192.168.1.0 0.0.0.255 any range 20-21",
                "access-list 102 permit tcp 192.168.1.0 0.0.0.255 172.16.0.0 0.0.255.255 eq 80",
                "access-list 102 permit tcp any any eq 22",
                "interface E0",
                "ip access-group 102 out");
        Files.writeString(aclFile, aclContent);

        Path packetsFile = tempDir.resolve("packets.txt");
        String packetsContent = String.join("\n",
                "192.168.1.100 172.16.1.1 20",     // Should be denied by first rule (port range)
                "192.168.1.50 172.16.1.1 80",      // Should be permitted by second rule
                "172.16.1.1 192.168.1.1 22",       // Should be permitted by third rule
                "192.168.1.1 10.0.0.1 80");        // Should be denied (implicit)
        Files.writeString(packetsFile, packetsContent);

        acl.loadRules(aclFile.toString());
        acl.processPackets(packetsFile.toString());

        String output = outContent.toString().replace("\r\n", "\n");
        String expectedOutput = String.join("\n",
                "Packet from 192.168.1.100 to 172.16.1.1 on port 20 denied",
                "Packet from 192.168.1.50 to 172.16.1.1 on port 80 permitted",
                "Packet from 172.16.1.1 to 192.168.1.1 on port 22 permitted",
                "Packet from 192.168.1.1 to 10.0.0.1 on port 80 denied",
                "");

        assertEquals(expectedOutput, output);
    }

    @Test
    void testServiceBasedRules() throws IOException {
        Path aclFile = tempDir.resolve("acl.txt");
        String aclContent = String.join("\n",
                "access-list 103 permit tcp 10.0.0.0 0.0.0.255 any eq 80",
                "access-list 103 permit tcp 10.0.0.0 0.0.0.255 any eq 443",
                "access-list 103 permit udp any any eq 53",
                "access-list 103 deny ip any 192.168.100.0 0.0.0.255",
                "interface E0",
                "ip access-group 103 out");
        Files.writeString(aclFile, aclContent);

        Path packetsFile = tempDir.resolve("packets.txt");
        String packetsContent = String.join("\n",
                "10.0.0.50 172.16.1.1 80",
                "10.1.0.50 172.16.1.1 80",
                "172.16.1.1 192.168.100.1",
                "172.16.1.1 8.8.8.8 53");
        Files.writeString(packetsFile, packetsContent);

        acl.loadRules(aclFile.toString());
        acl.processPackets(packetsFile.toString());

        String output = outContent.toString().replace("\r\n", "\n");
        String expectedOutput = String.join("\n",
                "Packet from 10.0.0.50 to 172.16.1.1 on port 80 permitted",
                "Packet from 10.1.0.50 to 172.16.1.1 on port 80 denied",
                "Packet from 172.16.1.1 to 192.168.100.1 denied",
                "Packet from 172.16.1.1 to 8.8.8.8 on port 53 permitted",
                "");

        assertEquals(expectedOutput, output);
    }

    @Test
    void testImplicitDeny() throws IOException {
        Path aclFile = tempDir.resolve("acl.txt");
        String aclContent = String.join("\n",
                "access-list 101 permit tcp 192.168.1.0 0.0.0.255 10.0.0.0 0.0.0.255 eq 80",
                "interface E0",
                "ip access-group 101 out");
        Files.writeString(aclFile, aclContent);

        Path packetsFile = tempDir.resolve("packets.txt");
        String packetsContent = String.join("\n",
                "172.16.1.1 10.0.0.1 80",
                "192.168.1.1 172.16.1.1 80");
        Files.writeString(packetsFile, packetsContent);

        acl.loadRules(aclFile.toString());
        acl.processPackets(packetsFile.toString());

        String output = outContent.toString().replace("\r\n", "\n");
        String expectedOutput = String.join("\n",
                "Packet from 172.16.1.1 to 10.0.0.1 on port 80 denied",
                "Packet from 192.168.1.1 to 172.16.1.1 on port 80 denied",
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

        Path packetsFile = tempDir.resolve("packets.txt");
        Files.writeString(packetsFile, "192.168.1.1 10.0.0.1 80");

        acl.loadRules(aclFile.toString());
        acl.processPackets(packetsFile.toString());

        String output = outContent.toString().replace("\r\n", "\n");
        String expectedOutput = "Packet from 192.168.1.1 to 10.0.0.1 on port 80 denied\n";

        assertEquals(expectedOutput, output);
    }
}