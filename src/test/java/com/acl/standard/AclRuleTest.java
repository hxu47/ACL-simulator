package com.acl.standard;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

public class AclRuleTest {

    @Test
    public void testAclRuleParser() {
        // Test parsing of a permit rule
        AclRule permitRule = new AclRule("access-list 3 permit 172.16.0.0 0.0.255.255");
        assertEquals(3, permitRule.getAclNumber());
        assertTrue(permitRule.isPermit());

        // Test parsing of a deny rule
        AclRule denyRule = new AclRule("access-list 3 deny 172.16.4.0 0.0.0.255");
        assertEquals(3, denyRule.getAclNumber());
        assertFalse(denyRule.isPermit());
    }

    @Test
    public void testIPMatching() {
        // Test exact IP matching
        AclRule exactRule = new AclRule("access-list 1 permit 192.168.1.1 0.0.0.0");
        assertTrue(exactRule.matches("192.168.1.1"));
        assertFalse(exactRule.matches("192.168.1.2"));

        // Test subnet matching with wildcard
        AclRule subnetRule = new AclRule("access-list 2 permit 172.16.0.0 0.0.255.255");
        assertTrue(subnetRule.matches("172.16.1.1"));
        assertTrue(subnetRule.matches("172.16.2.1"));
        assertFalse(subnetRule.matches("172.17.1.1"));

        // Test specific network matching
        AclRule networkRule = new AclRule("access-list 3 deny 172.16.4.0 0.0.0.255");
        assertTrue(networkRule.matches("172.16.4.1"));
        assertTrue(networkRule.matches("172.16.4.254"));
        assertFalse(networkRule.matches("172.16.5.1"));
    }

    @Test
    public void testEdgeCases() {
        // Test rule without wildcard mask (should default to 0.0.0.0)
        AclRule noWildcardRule = new AclRule("access-list 4 permit 192.168.1.1");
        assertTrue(noWildcardRule.matches("192.168.1.1"));
        assertFalse(noWildcardRule.matches("192.168.1.2"));

        // Test with "any" by using 255.255.255.255 wildcard
        AclRule anyRule = new AclRule("access-list 5 permit 0.0.0.0 255.255.255.255");
        assertTrue(anyRule.matches("192.168.1.1"));
        assertTrue(anyRule.matches("10.0.0.1"));
        assertTrue(anyRule.matches("172.16.0.1"));
    }
}