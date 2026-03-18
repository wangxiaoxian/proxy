# proxy
自定义vpn代理脚本

## 环境要求

- JDK 17
- Maven 3.9+

项目已在 `pom.xml` 中固定为 Java 17 编译，并通过 Maven Enforcer 限制运行构建的 JDK 版本为 `17.x`。

## 说明

- 代理主入口：`com.example.proxy.HttpProxyServer`
- 证书生成工具：`com.example.proxy.CertificateUtil`
- `CertificateUtil` 已改为使用 Bouncy Castle 生成证书，避免依赖 `sun.security.x509` 这类 JDK 内部 API
