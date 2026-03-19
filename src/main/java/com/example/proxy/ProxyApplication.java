package com.example.proxy;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Path;

public final class ProxyApplication {
    private static final Logger log = LoggerFactory.getLogger(ProxyApplication.class);

    private ProxyApplication() {
    }

    public static void main(String[] args) throws Exception {
        Path configPath = args.length > 0 ? Path.of(args[0]) : Path.of("proxy.yaml");
        ProxyConfig config = ProxyConfig.load(configPath);
        CertificateAuthority certificateAuthority = new CertificateAuthority(config.tls);
        certificateAuthority.initialize();
        HeaderRewriteEngine rewriteEngine = new HeaderRewriteEngine(config);
        ProxyServer proxyServer = new ProxyServer(config, rewriteEngine, certificateAuthority);
        log.info("Loaded config from {}", configPath.toAbsolutePath());
        proxyServer.start();
    }
}
