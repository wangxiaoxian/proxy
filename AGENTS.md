# AGENTS.md

## 目标
- 这是一个面向自有系统受控测试的 HTTP/HTTPS MITM 代理项目。
- 主要用途是拦截 HTTP 和 HTTPS 请求，并按配置修改请求头，用于模拟多个设备同时登录同一账号的测试场景。
- 当前实现方向参考 Charles/Fiddler 的显式代理模式，但范围严格限定在测试环境。

## 当前架构
- 主入口：`src/main/java/com/example/proxy/ProxyApplication.java`
- 配置模型：`src/main/java/com/example/proxy/ProxyConfig.java`
- 代理主链路：`src/main/java/com/example/proxy/ProxyServer.java`
- HTTPS 证书与 MITM：`src/main/java/com/example/proxy/CertificateAuthority.java`
- HTTP 请求解析：`src/main/java/com/example/proxy/HttpMessageReader.java`
- 请求头改写：`src/main/java/com/example/proxy/HeaderRewriteEngine.java`
- 示例配置：`proxy.yaml`
- 使用说明：`README.md`

## 已确定的设计约束
- 只服务于自有系统或明确授权的受控测试，不做第三方平台绕过设计。
- 只支持显式代理，不做透明代理。
- v1 只支持 HTTP/1.1，不支持 HTTP/2、WebSocket、gRPC。
- HTTPS MITM 采用“固定根 CA + 按目标域名动态签发叶子证书”的标准模式。
- 根 CA 首次生成后持久化复用，服务重启后不重新生成，避免客户端重复安装证书。
- 根 CA 有效期设置为长期有效，当前默认 10950 天；叶子证书默认 1825 天。
- 同名请求头按最后值覆盖，不保留重复头语义。
- 代理允许拦截所有域名，但请求头改写只对命中规则的域名生效；未命中规则的域名默认透传。
- profile 选择方式固定为“监听端口 -> profile”映射。

## 运行方式
- 环境要求：JDK 17，Maven 3.9+
- 启动前需要设置 CA 密码环境变量：`PROXY_CA_PASSWORD`
- 默认配置文件：`proxy.yaml`
- 启动方式：
  `mvn exec:java -Dexec.mainClass=com.example.proxy.ProxyApplication -Dexec.args="proxy.yaml"`

## 构建与测试
- 单元测试：`mvn -o test`
- 打包：`mvn -o package -DskipTests`
- 如果本机 Maven 默认仓库不可写或网络受限，优先使用离线模式或工作区内可写仓库。

## Codex 工作要求
- 修改前优先阅读 `README.md`、`PLANS.md`、`proxy.yaml` 和相关实现文件。
- 不要把新的架构决策只留在对话里；只要决策稳定，就同步更新 `PLANS.md` 或 `README.md`。
- 不要引入与当前目标无关的复杂功能，例如 UI、脚本引擎、插件系统。
- 不要弱化 TLS 上游证书校验，也不要实现证书锁定绕过能力。
- 如需改变已确定的核心约束，先更新 `PLANS.md` 中的决策，再实施代码修改。

## 完成标准
- 代码能离线通过：`mvn -o test`
- 打包能通过：`mvn -o package -DskipTests`
- 新能力必须反映到 `README.md` 或 `PLANS.md`
- 如果实现边界发生变化，需要明确写出新增能力、限制和未完成项
