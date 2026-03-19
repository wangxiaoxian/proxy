package com.example.proxy;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class CertificateAuthority {
    private final ProxyConfig.TlsConfig tlsConfig;
    private final char[] keyStorePassword;
    private final Path caKeyStorePath;
    private final Path caCertPath;
    private final Path certCacheDir;
    private final Map<String, SSLContext> sslContextCache = new ConcurrentHashMap<>();

    private KeyPair caKeyPair;
    private X509Certificate caCertificate;

    public CertificateAuthority(ProxyConfig.TlsConfig tlsConfig) {
        this.tlsConfig = tlsConfig;
        String password = System.getenv(tlsConfig.ca.keyStorePasswordEnv);
        if (password == null || password.isBlank()) {
            password = System.getProperty(tlsConfig.ca.keyStorePasswordEnv);
        }
        if (password == null || password.isBlank()) {
            throw new IllegalStateException("Environment variable is required: " + tlsConfig.ca.keyStorePasswordEnv);
        }
        this.keyStorePassword = password.toCharArray();
        this.caKeyStorePath = Path.of(tlsConfig.ca.keyStorePath);
        this.caCertPath = Path.of(tlsConfig.ca.certPath);
        this.certCacheDir = Path.of(tlsConfig.certCacheDir);
    }

    public synchronized void initialize() throws IOException, GeneralSecurityException {
        ensureProvider();
        Files.createDirectories(caKeyStorePath.getParent());
        Files.createDirectories(caCertPath.getParent());
        Files.createDirectories(certCacheDir);
        if (Files.exists(caKeyStorePath) && Files.exists(caCertPath)) {
            loadExistingCa();
            return;
        }
        if (Files.exists(caKeyStorePath) ^ Files.exists(caCertPath)) {
            throw new IOException("CA files are incomplete; delete both or restore both");
        }
        generateAndPersistCa();
    }

    public X509Certificate getCaCertificate() {
        return caCertificate;
    }

    public SSLContext serverSslContextForHost(String host) throws GeneralSecurityException, IOException {
        return sslContextCache.computeIfAbsent(host, key -> {
            try {
                return createLeafSslContext(key);
            } catch (GeneralSecurityException | IOException e) {
                throw new IllegalStateException("Failed to build SSL context for host: " + key, e);
            }
        });
    }

    private SSLContext createLeafSslContext(String host) throws GeneralSecurityException, IOException {
        KeyStore keyStore = ensureLeafKeyStore(host);
        KeyManagerFactory keyManagerFactory =
                KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyManagerFactory.init(keyStore, keyStorePassword);
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(keyManagerFactory.getKeyManagers(), null, null);
        return sslContext;
    }

    private KeyStore ensureLeafKeyStore(String host) throws GeneralSecurityException, IOException {
        Path leafPath = certCacheDir.resolve(sanitize(host) + ".p12");
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        if (Files.exists(leafPath)) {
            try (var inputStream = Files.newInputStream(leafPath)) {
                keyStore.load(inputStream, keyStorePassword);
            }
            return keyStore;
        }

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair leafKeyPair = keyPairGenerator.generateKeyPair();
        X509Certificate leafCertificate = generateLeafCertificate(host, leafKeyPair);
        keyStore.load(null, null);
        keyStore.setKeyEntry("leaf", leafKeyPair.getPrivate(), keyStorePassword,
                new java.security.cert.Certificate[]{leafCertificate, caCertificate});
        try (var outputStream = Files.newOutputStream(leafPath)) {
            keyStore.store(outputStream, keyStorePassword);
        }
        return keyStore;
    }

    private void generateAndPersistCa() throws GeneralSecurityException, IOException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        caKeyPair = keyPairGenerator.generateKeyPair();
        Instant now = Instant.now();
        Date notBefore = Date.from(now.minus(1, ChronoUnit.DAYS));
        Date notAfter = Date.from(now.plus(tlsConfig.ca.validityDays, ChronoUnit.DAYS));
        X500Name subject = new X500Name(tlsConfig.ca.distinguishedName);
        BigInteger serial = new BigInteger(128, new SecureRandom()).abs();

        try {
            JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                    subject, serial, notBefore, notAfter, subject, caKeyPair.getPublic());
            JcaX509ExtensionUtils extensionUtils = new JcaX509ExtensionUtils();
            builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
            builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
            builder.addExtension(Extension.subjectKeyIdentifier, false,
                    extensionUtils.createSubjectKeyIdentifier(caKeyPair.getPublic()));
            builder.addExtension(Extension.authorityKeyIdentifier, false,
                    extensionUtils.createAuthorityKeyIdentifier(caKeyPair.getPublic()));

            ContentSigner signer = contentSigner(caKeyPair.getPrivate());
            X509CertificateHolder holder = builder.build(signer);
            caCertificate = new JcaX509CertificateConverter()
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .getCertificate(holder);
            persistCa();
        } catch (OperatorCreationException e) {
            throw new GeneralSecurityException("Failed to generate root CA", e);
        }
    }

    private X509Certificate generateLeafCertificate(String host, KeyPair leafKeyPair)
            throws GeneralSecurityException, IOException {
        try {
            Instant now = Instant.now();
            Date notBefore = Date.from(now.minus(1, ChronoUnit.DAYS));
            Date notAfter = Date.from(now.plus(tlsConfig.leaf.validityDays, ChronoUnit.DAYS));
            X500Name subject = new X500Name("CN=" + host);
            JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                    caCertificate,
                    new BigInteger(128, new SecureRandom()).abs(),
                    notBefore,
                    notAfter,
                    subject,
                    leafKeyPair.getPublic()
            );
            GeneralNames subjectAltNames = new GeneralNames(new GeneralName(GeneralName.dNSName, host));
            builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
            builder.addExtension(Extension.keyUsage, true,
                    new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));
            builder.addExtension(Extension.extendedKeyUsage, false,
                    new org.bouncycastle.asn1.x509.ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth));
            builder.addExtension(Extension.subjectAlternativeName, false, subjectAltNames);

            ContentSigner signer = contentSigner(caKeyPair.getPrivate());
            X509CertificateHolder holder = builder.build(signer);
            return new JcaX509CertificateConverter()
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .getCertificate(holder);
        } catch (OperatorCreationException e) {
            throw new GeneralSecurityException("Failed to generate leaf certificate", e);
        }
    }

    private void persistCa() throws GeneralSecurityException, IOException {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null, null);
        keyStore.setKeyEntry("ca", caKeyPair.getPrivate(), keyStorePassword,
                new java.security.cert.Certificate[]{caCertificate});
        try (var outputStream = Files.newOutputStream(caKeyStorePath)) {
            keyStore.store(outputStream, keyStorePassword);
        }
        Files.writeString(caCertPath, pem(caCertificate), StandardCharsets.US_ASCII);
    }

    private void loadExistingCa() throws IOException, GeneralSecurityException {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (var inputStream = Files.newInputStream(caKeyStorePath)) {
            keyStore.load(inputStream, keyStorePassword);
        }
        java.security.Key key = keyStore.getKey("ca", keyStorePassword);
        if (!(key instanceof PrivateKey privateKey)) {
            throw new GeneralSecurityException("CA private key missing from keystore");
        }
        java.security.cert.Certificate certificate = keyStore.getCertificate("ca");
        if (!(certificate instanceof X509Certificate x509Certificate)) {
            throw new GeneralSecurityException("CA certificate missing from keystore");
        }
        caKeyPair = new KeyPair(x509Certificate.getPublicKey(), privateKey);
        caCertificate = x509Certificate;
    }

    private static ContentSigner contentSigner(PrivateKey privateKey)
            throws OperatorCreationException {
        return new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(privateKey);
    }

    private static void ensureProvider() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private static String sanitize(String host) {
        return host.replaceAll("[^A-Za-z0-9._-]", "_");
    }

    private static String pem(X509Certificate certificate) throws CertificateEncodingException {
        String body = Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(certificate.getEncoded());
        return "-----BEGIN CERTIFICATE-----\n" + body + "\n-----END CERTIFICATE-----\n";
    }
}
