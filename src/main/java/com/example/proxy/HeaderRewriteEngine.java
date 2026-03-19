package com.example.proxy;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

public class HeaderRewriteEngine {
    private final List<CompiledTargetRule> targetRules = new ArrayList<>();
    private final List<ProxyConfig.HeaderActionConfig> globalActions = new ArrayList<>();

    public HeaderRewriteEngine(ProxyConfig config) {
        for (ProxyConfig.RuleConfig globalRule : config.rewrite.globalRules) {
            globalActions.addAll(globalRule.actions);
        }
        for (ProxyConfig.TargetRuleConfig rule : config.rewrite.targetRules) {
            targetRules.add(new CompiledTargetRule(rule));
        }
    }

    public List<String> apply(ParsedHttpRequest request, String host, ProxyConfig.ProfileConfig profile) {
        List<String> applied = new ArrayList<>();
        for (ProxyConfig.HeaderActionConfig action : globalActions) {
            applyAction(request, action, applied);
        }
        if (profile != null && profile.headers != null) {
            for (var entry : profile.headers.entrySet()) {
                request.setHeader(entry.getKey(), entry.getValue());
                applied.add("profile:set:" + entry.getKey());
            }
        }
        for (CompiledTargetRule rule : targetRules) {
            if (rule.matches(host)) {
                for (ProxyConfig.HeaderActionConfig action : rule.actions) {
                    applyAction(request, action, applied);
                }
            }
        }
        return applied;
    }

    private void applyAction(ParsedHttpRequest request,
                             ProxyConfig.HeaderActionConfig action,
                             List<String> applied) {
        if (action == null || action.name == null || action.action == null) {
            return;
        }
        switch (action.action.toLowerCase(Locale.ROOT)) {
            case "set" -> {
                request.setHeader(action.name, action.value == null ? "" : action.value);
                applied.add("set:" + action.name);
            }
            case "remove" -> {
                request.removeHeader(action.name);
                applied.add("remove:" + action.name);
            }
            case "append" -> {
                String current = request.header(action.name);
                String next = current == null || current.isEmpty()
                        ? action.value
                        : current + (action.value == null ? "" : action.value);
                request.setHeader(action.name, next);
                applied.add("append:" + action.name);
            }
            case "set_if_absent" -> {
                if (!request.hasHeader(action.name)) {
                    request.setHeader(action.name, action.value == null ? "" : action.value);
                    applied.add("set_if_absent:" + action.name);
                }
            }
            default -> throw new IllegalArgumentException("Unsupported header action: " + action.action);
        }
    }

    private static class CompiledTargetRule {
        private final List<String> hosts;
        private final List<ProxyConfig.HeaderActionConfig> actions;

        private CompiledTargetRule(ProxyConfig.TargetRuleConfig config) {
            this.hosts = config.hosts == null ? List.of() : config.hosts;
            this.actions = config.actions == null ? List.of() : config.actions;
        }

        private boolean matches(String host) {
            if (host == null) {
                return false;
            }
            String lowerHost = host.toLowerCase(Locale.ROOT);
            for (String pattern : hosts) {
                String lowerPattern = pattern.toLowerCase(Locale.ROOT);
                if (lowerPattern.startsWith("*.")) {
                    String suffix = lowerPattern.substring(1);
                    if (lowerHost.endsWith(suffix)) {
                        return true;
                    }
                } else if (lowerHost.equals(lowerPattern)) {
                    return true;
                }
            }
            return false;
        }
    }
}
