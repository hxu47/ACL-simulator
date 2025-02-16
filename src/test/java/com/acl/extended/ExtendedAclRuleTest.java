package com.acl.extended;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

public class ExtendedAclRuleTest {

    @Test
    public void testProtocolParsing() {
        // Test TCP protocol with port
        ExtendedAclRule tcpRule = new ExtendedAclRule(
                "access-list 101 deny tcp 172.16.0.0 0.0.255.255 172.16.3.0 0.0.0.255 eq 80"
        );
        assertEquals("tcp", tcpRule.getProtocol());

        // Test UDP protocol with port
        ExtendedAclRule udpRule = new ExtendedAclRule(
                "access-list 101 deny udp 172.16.0.0 0.0.255.255 172.16.3.0 0.0.0.255 eq 53"
        );
        assertEquals("udp", udpRule.getProtocol());

        // Test IP protocol (no port)
        ExtendedAclRule ipRule = new ExtendedAclRule(
                "access-list 101 permit ip 172.16.0.0 0.0.255.255 172.16.3.0 0.0.0.255"
        );
        assertEquals("ip", ipRule.getProtocol());

        // Test ICMP protocol (no port)
        ExtendedAclRule icmpRule = new ExtendedAclRule(
                "access-list 101 permit icmp 172.16.0.0 0.0.255.255 172.16.3.0 0.0.0.255"
        );
        assertEquals("icmp", icmpRule.getProtocol());

        // Test IGMP protocol (no port)
        ExtendedAclRule igmpRule = new ExtendedAclRule(
                "access-list 101 permit igmp 172.16.0.0 0.0.255.255 172.16.3.0 0.0.0.255"
        );
        assertEquals("igmp", igmpRule.getProtocol());
    }

    @Test
    public void testPortlessProtocolMatching() {
        // Test ICMP protocol rule (should ignore ports)
        ExtendedAclRule icmpRule = new ExtendedAclRule(
                "access-list 101 permit icmp 172.16.0.0 0.0.255.255 172.16.3.0 0.0.0.255"
        );

        // Should match regardless of port number
        assertTrue(icmpRule.matches("172.16.4.4", "172.16.3.5", 80));
        assertTrue(icmpRule.matches("172.16.4.4", "172.16.3.5", 443));

        // Should not match for wrong IP
        assertFalse(icmpRule.matches("172.17.4.4", "172.16.3.5", 80));

        // Test IGMP protocol rule (should ignore ports)
        ExtendedAclRule igmpRule = new ExtendedAclRule(
                "access-list 101 permit igmp 172.16.0.0 0.0.255.255 172.16.3.0 0.0.0.255"
        );

        // Should match regardless of port number
        assertTrue(igmpRule.matches("172.16.4.4", "172.16.3.5", 80));
        assertTrue(igmpRule.matches("172.16.4.4", "172.16.3.5", 443));
    }

    @Test
    public void testPortMatching() {
        // Test single port matching
        ExtendedAclRule singlePortRule = new ExtendedAclRule(
                "access-list 101 deny tcp 172.16.0.0 0.0.255.255 172.16.3.0 0.0.0.255 eq 80"
        );

        // Match exact port
        assertTrue(singlePortRule.matches("172.16.4.4", "172.16.3.1", 80));
        // Don't match different port
        assertFalse(singlePortRule.matches("172.16.4.4", "172.16.3.1", 81));

        // Test port range matching
        ExtendedAclRule portRangeRule = new ExtendedAclRule(
                "access-list 101 deny tcp 172.16.0.0 0.0.255.255 172.16.3.0 0.0.0.255 range 20-25"
        );

        // Match ports within range
        assertTrue(portRangeRule.matches("172.16.4.4", "172.16.3.1", 20));
        assertTrue(portRangeRule.matches("172.16.4.4", "172.16.3.1", 22));
        assertTrue(portRangeRule.matches("172.16.4.4", "172.16.3.1", 25));

        // Don't match ports outside range
        assertFalse(portRangeRule.matches("172.16.4.4", "172.16.3.1", 19));
        assertFalse(portRangeRule.matches("172.16.4.4", "172.16.3.1", 26));
    }

    @Test
    public void testTCPUDPProtocolMatching() {
        // Test TCP protocol with port range
        ExtendedAclRule tcpRule = new ExtendedAclRule(
                "access-list 101 deny tcp 172.16.0.0 0.0.255.255 172.16.3.0 0.0.0.255 range 20-21"
        );

        assertTrue(tcpRule.matches("172.16.4.4", "172.16.3.1", 20));
        assertFalse(tcpRule.matches("172.16.4.4", "172.16.3.1", 22));

        // Test UDP protocol with single port
        ExtendedAclRule udpRule = new ExtendedAclRule(
                "access-list 101 deny udp 172.16.0.0 0.0.255.255 172.16.3.0 0.0.0.255 eq 53"
        );

        assertTrue(udpRule.matches("172.16.4.4", "172.16.3.1", 53));
        assertFalse(udpRule.matches("172.16.4.4", "172.16.3.1", 54));
    }

    @Test
    public void testAnyKeywordParsing() {
        // Test with 'any' for both source and destination
        ExtendedAclRule anyRule = new ExtendedAclRule(
                "access-list 101 permit tcp any any eq 80"
        );

        // Should match any source and destination IPs
        assertTrue(anyRule.matches("192.168.1.1", "10.0.0.1", 80));
        assertTrue(anyRule.matches("172.16.1.1", "172.16.1.1", 80));
        // But should still respect port
        assertFalse(anyRule.matches("192.168.1.1", "10.0.0.1", 443));

        // Test with 'any' for source only
        ExtendedAclRule sourceAnyRule = new ExtendedAclRule(
                "access-list 101 permit tcp any 172.16.3.0 0.0.0.255 eq 80"
        );

        // Should match any source IP but specific destination
        assertTrue(sourceAnyRule.matches("192.168.1.1", "172.16.3.1", 80));
        assertFalse(sourceAnyRule.matches("192.168.1.1", "172.16.4.1", 80));

        // Test with 'any' for destination only
        ExtendedAclRule destAnyRule = new ExtendedAclRule(
                "access-list 101 permit tcp 172.16.0.0 0.0.255.255 any eq 80"
        );

        // Should match specific source but any destination
        assertTrue(destAnyRule.matches("172.16.1.1", "192.168.1.1", 80));
        assertFalse(destAnyRule.matches("172.17.1.1", "192.168.1.1", 80));
    }

    @Test
    public void testPortlessPackets() {
        // Test rule without port specification
        ExtendedAclRule ipRule = new ExtendedAclRule(
                "access-list 101 permit ip 172.16.0.0 0.0.255.255 172.16.3.0 0.0.0.255"
        );

        // Should match packet without port
        assertTrue(ipRule.matches("172.16.4.4", "172.16.3.5", null));
        // Should also match packet with port (since IP protocol ignores ports)
        assertTrue(ipRule.matches("172.16.4.4", "172.16.3.5", 80));

        // Test TCP rule with port specification
        ExtendedAclRule tcpRule = new ExtendedAclRule(
                "access-list 101 permit tcp 172.16.0.0 0.0.255.255 172.16.3.0 0.0.0.255 eq 80"
        );

        // Should not match packet without port
        assertFalse(tcpRule.matches("172.16.4.4", "172.16.3.5", null));
        // Should match packet with correct port
        assertTrue(tcpRule.matches("172.16.4.4", "172.16.3.5", 80));

        // Test TCP rule without port specification
        ExtendedAclRule tcpNoPortRule = new ExtendedAclRule(
                "access-list 101 permit tcp 172.16.0.0 0.0.255.255 172.16.3.0 0.0.0.255"
        );

        // Should match packet without port
        assertTrue(tcpNoPortRule.matches("172.16.4.4", "172.16.3.5", null));
        // Should match packet with any port
        assertTrue(tcpNoPortRule.matches("172.16.4.4", "172.16.3.5", 80));
        assertTrue(tcpNoPortRule.matches("172.16.4.4", "172.16.3.5", 443));
    }

    @Test
    public void testEdgeCases() {
        // Test protocol with "any any"
        ExtendedAclRule ipRule = new ExtendedAclRule(
                "access-list 101 permit ip 0.0.0.0 255.255.255.255 0.0.0.0 255.255.255.255"
        );

        assertTrue(ipRule.matches("192.168.1.1", "10.0.0.1", 80));

        // Test TCP with "any any" but specific port
        ExtendedAclRule tcpRule = new ExtendedAclRule(
                "access-list 101 permit tcp 0.0.0.0 255.255.255.255 0.0.0.0 255.255.255.255 eq 80"
        );

        assertTrue(tcpRule.matches("192.168.1.1", "10.0.0.1", 80));
        assertFalse(tcpRule.matches("192.168.1.1", "10.0.0.1", 443));
    }
}