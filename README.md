# proxy

面向自有系统受控测试的 HTTP/HTTPS MITM 代理。它支持显式代理、固定根 CA、按目标域名动态签发叶子证书，以及基于配置的请求头改写。

## 环境要求

- JDK 17
- Maven 3.9+
- 环境变量 `PROXY_CA_PASSWORD`

## 快速开始

1. 复制并编辑 `proxy.yaml`
2. 设置根 CA 密码，例如 `export PROXY_CA_PASSWORD=changeit`
3. 启动代理：`mvn exec:java -Dexec.mainClass=com.example.proxy.ProxyApplication -Dexec.args="proxy.yaml"`
4. 首次启动后会生成固定根证书，将 `tls.ca.certPath` 指向的 `.cer` 安装到测试客户端受信任根证书列表
5. 将客户端 HTTP/HTTPS 代理指向配置中的监听端口

## 当前能力

- HTTP/1.1 显式代理
- `CONNECT` + HTTPS MITM
- 固定根 CA，重启后复用
- 按监听端口绑定 profile
- 按域名规则改写请求头
- 本地只读管理接口：
  - `/_admin/health`
  - `/_admin/config`
  - `/_admin/recent-requests`

## 限制

- 仅支持 HTTP/1.1
- 不支持 HTTP/2、WebSocket、gRPC
- 不处理第三方 App 证书锁定
