package com.example.proxy;

import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.TypeDescription;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.Constructor;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

public class ProxyConfig {
    public ServerConfig server = new ServerConfig();
    public TlsConfig tls = new TlsConfig();
    public RewriteConfig rewrite = new RewriteConfig();
    public List<ProfileConfig> profiles = new ArrayList<>();
    public AdminConfig admin = new AdminConfig();

    public static ProxyConfig load(Path path) throws IOException {
        LoaderOptions loaderOptions = new LoaderOptions();
        Constructor constructor = new Constructor(ProxyConfig.class, loaderOptions);
        TypeDescription configDescription = new TypeDescription(ProxyConfig.class);
        configDescription.putListPropertyType("profiles", ProfileConfig.class);
        constructor.addTypeDescription(configDescription);

        TypeDescription serverDescription = new TypeDescription(ServerConfig.class);
        serverDescription.putListPropertyType("listeners", ListenerConfig.class);
        constructor.addTypeDescription(serverDescription);

        TypeDescription rewriteDescription = new TypeDescription(RewriteConfig.class);
        rewriteDescription.putListPropertyType("globalRules", RuleConfig.class);
        rewriteDescription.putListPropertyType("targetRules", TargetRuleConfig.class);
        constructor.addTypeDescription(rewriteDescription);

        TypeDescription targetRuleDescription = new TypeDescription(TargetRuleConfig.class);
        targetRuleDescription.putListPropertyType("hosts", String.class);
        targetRuleDescription.putListPropertyType("actions", HeaderActionConfig.class);
        constructor.addTypeDescription(targetRuleDescription);

        TypeDescription ruleDescription = new TypeDescription(RuleConfig.class);
        ruleDescription.putListPropertyType("actions", HeaderActionConfig.class);
        constructor.addTypeDescription(ruleDescription);

        try (InputStream inputStream = Files.newInputStream(path)) {
            Yaml yaml = new Yaml(constructor);
            ProxyConfig config = yaml.loadAs(inputStream, ProxyConfig.class);
            if (config == null) {
                throw new IOException("Configuration file is empty: " + path);
            }
            config.validate();
            return config;
        }
    }

    public void validate() {
        if (server.listeners == null || server.listeners.isEmpty()) {
            throw new IllegalArgumentException("At least one listener must be configured");
        }
        if (profiles == null || profiles.isEmpty()) {
            throw new IllegalArgumentException("At least one profile must be configured");
        }
        Map<String, ProfileConfig> profilesById = new HashMap<>();
        for (ProfileConfig profile : profiles) {
            if (profile.id == null || profile.id.isBlank()) {
                throw new IllegalArgumentException("Profile id must not be blank");
            }
            profilesById.put(profile.id, profile);
        }
        for (ListenerConfig listener : server.listeners) {
            if (listener.port <= 0) {
                throw new IllegalArgumentException("Listener port must be positive");
            }
            if (!profilesById.containsKey(listener.profileId)) {
                throw new IllegalArgumentException("Listener references unknown profile: " + listener.profileId);
            }
        }
        Objects.requireNonNull(tls.ca.keyStorePath, "tls.ca.keyStorePath");
        Objects.requireNonNull(tls.ca.certPath, "tls.ca.certPath");
        Objects.requireNonNull(tls.ca.keyStorePasswordEnv, "tls.ca.keyStorePasswordEnv");
        if (tls.ca.validityDays <= 0) {
            throw new IllegalArgumentException("tls.ca.validityDays must be positive");
        }
        if (tls.leaf.validityDays <= 0) {
            throw new IllegalArgumentException("tls.leaf.validityDays must be positive");
        }
    }

    public static class ServerConfig {
        public List<ListenerConfig> listeners = new ArrayList<>();
        public int socketTimeoutMillis = 30000;
        public int connectTimeoutMillis = 10000;
        public int maxWorkerThreads = 64;
    }

    public static class ListenerConfig {
        public int port;
        public String profileId;
    }

    public static class TlsConfig {
        public CaConfig ca = new CaConfig();
        public LeafConfig leaf = new LeafConfig();
        public String certCacheDir = ".proxy/cert-cache";
    }

    public static class CaConfig {
        public String certPath = ".proxy/ca/proxy-ca.cer";
        public String keyStorePath = ".proxy/ca/proxy-ca.p12";
        public String keyStorePasswordEnv = "PROXY_CA_PASSWORD";
        public int validityDays = 10950;
        public String distinguishedName = "CN=Proxy Test Root CA,O=Proxy,C=CN";
    }

    public static class LeafConfig {
        public int validityDays = 1825;
    }

    public static class RewriteConfig {
        public List<RuleConfig> globalRules = new ArrayList<>();
        public List<TargetRuleConfig> targetRules = new ArrayList<>();
        public List<String> redactHeaders = List.of("authorization", "cookie", "set-cookie", "x-auth-token");
    }

    public static class RuleConfig {
        public String id;
        public List<HeaderActionConfig> actions = new ArrayList<>();
    }

    public static class TargetRuleConfig extends RuleConfig {
        public List<String> hosts = new ArrayList<>();
    }

    public static class HeaderActionConfig {
        public String action;
        public String name;
        public String value;
    }

    public static class ProfileConfig {
        public String id;
        public Map<String, String> headers = new HashMap<>();
        public List<String> enabledDomains = new ArrayList<>();
    }

    public static class AdminConfig {
        public boolean enabled = true;
        public String host = "127.0.0.1";
        public int port = 9090;
    }
}
