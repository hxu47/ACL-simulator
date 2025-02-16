package com.acl.extended;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

public class ExtendedAclRuleTest {

    @Test
    public void testExtendedAclRuleParser() {
        // Test parsing of a TCP port range rule
        ExtendedAclRule portRangeRule = new ExtendedAclRule(
                "access-list 101 deny tcp 172.16.0.0 0.0.255.255 172.16.3.0 0.0.0.255 range 20-21"
        );
        assertEquals(101, portRangeRule.getAclNumber());
        assertFalse(portRangeRule.isPermit());

        // Test parsing of a single port rule
        ExtendedAclRule singlePortRule = new ExtendedAclRule(
                "access-list 101 deny tcp 172.16.0.0 0.0.255.255 172.16.3.0 0.0.0.255 eq 80"
        );
        assertEquals(101, singlePortRule.getAclNumber());
        assertFalse(singlePortRule.isPermit());

        // Test parsing of a general IP permit rule (no port)
        ExtendedAclRule ipPermitRule = new ExtendedAclRule(
                "access-list 101 permit ip 172.16.0.0 0.0.255.255 172.16.3.0 0.0.0.255"
        );
        assertEquals(101, ipPermitRule.getAclNumber());
        assertTrue(ipPermitRule.isPermit());
    }

    @Test
    public void testPortRangeMatching() {
        ExtendedAclRule rule = new ExtendedAclRule(
                "access-list 101 deny tcp 172.16.0.0 0.0.255.255 172.16.3.0 0.0.0.255 range 20-21"
        );

        // Test port within range
        assertTrue(rule.matches("172.16.4.4", "172.16.3.1", 20));
        assertTrue(rule.matches("172.16.4.4", "172.16.3.1", 21));

        // Test port outside range
        assertFalse(rule.matches("172.16.4.4", "172.16.3.1", 22));
        assertFalse(rule.matches("172.16.4.4", "172.16.3.1", 19));
    }

    @Test
    public void testSinglePortMatching() {
        ExtendedAclRule rule = new ExtendedAclRule(
                "access-list 101 deny tcp 172.16.0.0 0.0.255.255 172.16.3.0 0.0.0.255 eq 80"
        );

        // Test matching port
        assertTrue(rule.matches("172.16.4.4", "172.16.3.1", 80));

        // Test non-matching ports
        assertFalse(rule.matches("172.16.4.4", "172.16.3.1", 81));
        assertFalse(rule.matches("172.16.4.4", "172.16.3.1", 79));
    }

    @Test
    public void testIPMatching() {
        ExtendedAclRule rule = new ExtendedAclRule(
                "access-list 101 permit ip 172.16.0.0 0.0.255.255 172.16.3.0 0.0.0.255"
        );

        // Test matching source and destination IPs
        assertTrue(rule.matches("172.16.4.4", "172.16.3.5", 22));

        // Test non-matching source IP
        assertFalse(rule.matches("172.17.4.4", "172.16.3.5", 22));

        // Test non-matching destination IP
        assertFalse(rule.matches("172.16.4.4", "172.16.4.5", 22));
    }

    @Test
    public void testEdgeCases() {
        // Test rule without port specification
        ExtendedAclRule ipRule = new ExtendedAclRule(
                "access-list 101 permit ip 0.0.0.0 255.255.255.255 0.0.0.0 255.255.255.255"
        );

        // Should match any IP addresses when using "any any" (0.0.0.0 255.255.255.255)
        assertTrue(ipRule.matches("192.168.1.1", "10.0.0.1", 80));
        assertTrue(ipRule.matches("172.16.1.1", "172.16.1.1", 443));
    }
}