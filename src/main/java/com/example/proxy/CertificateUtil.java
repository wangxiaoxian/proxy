package com.example.proxy;

import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * 简单的证书工具：
 * - 生成自签名根 CA 证书
 * - 导出为 PKCS12 (.p12) 供代理端使用
 * - 导出为 .cer 供浏览器/系统导入信任
 *
 * 注意：示例代码仅用于开发/测试环境。
 */
public class CertificateUtil {

    public static class GeneratedCA {
        public final KeyPair keyPair;
        public final X509Certificate certificate;

        public GeneratedCA(KeyPair keyPair, X509Certificate certificate) {
            this.keyPair = keyPair;
            this.certificate = certificate;
        }
    }

    /**
     * 生成自签名 CA 证书。
     *
     * @param dn           证书主题，例如 "CN=MyProxy CA,O=MyOrg,C=CN"
     * @param days         有效天数
     * @param keySize      密钥长度，推荐 2048
     */
    public static GeneratedCA generateSelfSignedCA(String dn, int days, int keySize)
            throws GeneralSecurityException, IOException {
        ensureBouncyCastleProvider();

        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(keySize);
        KeyPair keyPair = keyPairGen.generateKeyPair();

        long now = System.currentTimeMillis();
        Date notBefore = new Date(now - 24L * 60 * 60 * 1000);
        Date notAfter = new Date(now + days * 24L * 60 * 60 * 1000);
        X500Name subject = new X500Name(dn);

        try {
            JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                    subject,
                    new java.math.BigInteger(64, new SecureRandom()),
                    notBefore,
                    notAfter,
                    subject,
                    keyPair.getPublic()
            );
            JcaX509ExtensionUtils extensionUtils = new JcaX509ExtensionUtils();
            builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
            builder.addExtension(Extension.keyUsage, true,
                    new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
            builder.addExtension(Extension.subjectKeyIdentifier, false,
                    extensionUtils.createSubjectKeyIdentifier(keyPair.getPublic()));
            builder.addExtension(Extension.authorityKeyIdentifier, false,
                    extensionUtils.createAuthorityKeyIdentifier(keyPair.getPublic()));

            ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .build(keyPair.getPrivate());
            X509CertificateHolder holder = builder.build(signer);
            X509Certificate cert = new JcaX509CertificateConverter()
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .getCertificate(holder);
            cert.verify(keyPair.getPublic());
            return new GeneratedCA(keyPair, cert);
        } catch (OperatorCreationException e) {
            throw new GeneralSecurityException("Failed to generate self-signed CA", e);
        }
    }

    private static void ensureBouncyCastleProvider() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /**
     * 将 CA 私钥 + 证书导出为 PKCS12 文件（.p12），供服务端使用。
     */
    public static void exportToPkcs12(GeneratedCA ca, String password, String path)
            throws GeneralSecurityException, IOException {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        ks.setKeyEntry("ca", ca.keyPair.getPrivate(), password.toCharArray(),
                new java.security.cert.Certificate[]{ca.certificate});

        try (FileOutputStream fos = new FileOutputStream(path)) {
            ks.store(fos, password.toCharArray());
        }
    }

    /**
     * 导出 CA 证书为 .cer（PEM 格式），供客户端导入信任。
     */
    public static void exportToCer(GeneratedCA ca, String path)
            throws IOException, CertificateEncodingException {
        byte[] der = ca.certificate.getEncoded();

        StringBuilder pem = new StringBuilder();
        pem.append("-----BEGIN CERTIFICATE-----\n");
        pem.append(Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(der));
        pem.append("\n-----END CERTIFICATE-----\n");

        try (FileOutputStream fos = new FileOutputStream(path)) {
            fos.write(pem.toString().getBytes());
        }
    }

    /**
     * 简单示例：生成一个 CA，并导出：
     * - proxy-ca.p12：服务端使用
     * - proxy-ca.cer：客户端导入信任
     */
    public static void main(String[] args) throws Exception {
        String dn = "CN=MyProxy CA,O=MyOrg,C=CN";
        GeneratedCA ca = generateSelfSignedCA(dn, 3650, 2048);

        String password = "changeit";
        exportToPkcs12(ca, password, "proxy-ca.p12");
        exportToCer(ca, "proxy-ca.cer");

        System.out.println("生成完成：proxy-ca.p12 / proxy-ca.cer");
        System.out.println("请将 proxy-ca.cer 导入到客户端/浏览器的受信任根证书中。");
    }
}
