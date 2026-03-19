package com.example.proxy;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.nio.file.Path;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertTrue;

public class CertificateAuthorityTest {
    @Rule
    public TemporaryFolder tempDir = new TemporaryFolder();

    @Test
    public void reusesPersistentCaAcrossRestarts() throws Exception {
        ProxyConfig.TlsConfig tlsConfig = new ProxyConfig.TlsConfig();
        Path root = tempDir.getRoot().toPath();
        tlsConfig.ca.keyStorePath = root.resolve("ca/proxy-ca.p12").toString();
        tlsConfig.ca.certPath = root.resolve("ca/proxy-ca.cer").toString();
        tlsConfig.certCacheDir = root.resolve("cache").toString();
        tlsConfig.ca.keyStorePasswordEnv = "PROXY_CA_PASSWORD";
        System.setProperty("PROXY_CA_PASSWORD", "changeit");

        CertificateAuthority first = new CertificateAuthority(tlsConfig);
        CertificateAuthority second = new CertificateAuthority(tlsConfig);

        first.initialize();
        byte[] firstEncoded = first.getCaCertificate().getEncoded();

        second.initialize();
        byte[] secondEncoded = second.getCaCertificate().getEncoded();

        assertArrayEquals(firstEncoded, secondEncoded);
        assertTrue(root.resolve("ca/proxy-ca.cer").toFile().exists());
    }
}
