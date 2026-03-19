package com.example.proxy;

import org.junit.Test;

import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class HeaderRewriteEngineTest {
    @Test
    public void appliesProfileAndTargetRulesWithLastValueSemantics() {
        ProxyConfig config = new ProxyConfig();
        ProxyConfig.TargetRuleConfig targetRule = new ProxyConfig.TargetRuleConfig();
        targetRule.hosts = List.of("api.example.com");
        ProxyConfig.HeaderActionConfig setAction = new ProxyConfig.HeaderActionConfig();
        setAction.action = "set";
        setAction.name = "User-Agent";
        setAction.value = "rule-agent";
        targetRule.actions = List.of(setAction);
        config.rewrite.targetRules = List.of(targetRule);

        ProxyConfig.ProfileConfig profile = new ProxyConfig.ProfileConfig();
        profile.id = "device-a";
        profile.headers.put("User-Agent", "profile-agent");
        profile.headers.put("X-Device-Id", "device-1");

        ParsedHttpRequest request = new ParsedHttpRequest();
        request.setHeader("User-Agent", "client-agent");

        HeaderRewriteEngine engine = new HeaderRewriteEngine(config);
        List<String> applied = engine.apply(request, "api.example.com", profile);

        assertEquals("rule-agent", request.header("User-Agent"));
        assertEquals("device-1", request.header("X-Device-Id"));
        assertTrue(applied.contains("profile:set:User-Agent"));
        assertTrue(applied.contains("set:User-Agent"));
    }
}
