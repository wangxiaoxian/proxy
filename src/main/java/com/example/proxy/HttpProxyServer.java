package com.example.proxy;

import javax.net.ssl.*;
import java.io.*;
import java.net.*;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * 一个简单的 HTTP 代理服务器，用于在浏览器中配置为“网络代理”。
 *
 * - 浏览器把请求发到本机代理 (host:port)
 * - 本服务读取原始 HTTP 报文，修改请求头，再转发到真实业务服务器
 *
 * 当前实现：
 * - 支持普通 HTTP 请求，并可对请求头做统一修改
 * - 对 HTTPS 的 CONNECT 方法做 MITM 终止 TLS，并转发到真实业务服务器
 *   （前提：客户端已信任本代理使用的证书）
 *
 * 要求：
 * - 使用 {@link CertificateUtil} 生成证书（例如 proxy-ca.p12/proxy-ca.cer）
 * - 将 proxy-ca.cer 导入浏览器/系统受信任根
 * - 确保 KEYSTORE_PATH/KEYSTORE_PASSWORD 指向正确的 .p12 文件
 */
public class HttpProxyServer {

    // 代理监听端口，浏览器里配置时需要用到，例如 8888
    private final int listenPort;

    // 可选：限制只允许代理到某个业务域名前缀（如果不限制，可以直接转发到请求里的 Host）
    // 例如你只允许访问某个后端：private static final String FORCE_TARGET_HOST = "api.xxx.com";
    private static final String FORCE_TARGET_HOST = null; // 为 null 表示不强制固定域名

    // MITM 用的服务端证书（PKCS12），由 CertificateUtil 生成
    private static final String KEYSTORE_PATH = "proxy-ca.p12";
    private static final String KEYSTORE_PASSWORD = "changeit";

    private static SSLContext SERVER_SSL_CONTEXT;
    private static SSLContext CLIENT_SSL_CONTEXT;

    private final ExecutorService executor = Executors.newCachedThreadPool();

    public HttpProxyServer(int listenPort) {
        this.listenPort = listenPort;
    }

    public void start() throws IOException {
        initSslContexts();
        ServerSocket serverSocket = new ServerSocket(listenPort);
        System.out.println("HTTP Proxy started on port " + listenPort);

        while (true) {
            Socket clientSocket = serverSocket.accept();
            executor.submit(() -> handleClient(clientSocket));
        }
    }

    private void handleClient(Socket clientSocket) {
        try (
                clientSocket;
                InputStream in = clientSocket.getInputStream();
                OutputStream out = clientSocket.getOutputStream();
                BufferedReader reader = new BufferedReader(new InputStreamReader(in));
                BufferedOutputStream clientWriter = new BufferedOutputStream(out)
        ) {
            String requestLine = reader.readLine();
            if (requestLine == null || requestLine.isEmpty()) {
                return;
            }

            // 示例：GET http://example.com/path HTTP/1.1
            StringTokenizer tokenizer = new StringTokenizer(requestLine);
            String method = tokenizer.nextToken();
            String uri = tokenizer.nextToken();
            String httpVersion = tokenizer.nextToken();

            if ("CONNECT".equalsIgnoreCase(method)) {
                handleHttpsMitm(requestLine, clientSocket);
                return;
            }

            // 读取请求头
            Map<String, String> headers = new LinkedHashMap<>();
            String line;
            int contentLength = 0;
            while ((line = reader.readLine()) != null && !line.isEmpty()) {
                int idx = line.indexOf(':');
                if (idx > 0) {
                    String name = line.substring(0, idx).trim();
                    String value = line.substring(idx + 1).trim();
                    headers.put(name, value);
                    if ("Content-Length".equalsIgnoreCase(name)) {
                        try {
                            contentLength = Integer.parseInt(value);
                        } catch (NumberFormatException ignored) {
                        }
                    }
                }
            }

            // 读取请求体（如果有）
            byte[] body = null;
            if (contentLength > 0) {
                body = in.readNBytes(contentLength);
            }

            // 解析目标 URL
            URL url;
            if (uri.startsWith("http://") || uri.startsWith("https://")) {
                url = new URL(uri);
            } else {
                // 某些情况下浏览器发送的是相对路径，此时从 Host 头拼装
                String host = headers.get("Host");
                if (host == null) {
                    sendBadRequest(clientWriter, "Missing Host header");
                    return;
                }
                url = new URL("http://" + host + uri);
            }

            String targetHost = FORCE_TARGET_HOST != null ? FORCE_TARGET_HOST : url.getHost();
            int targetPort = url.getPort() > 0 ? url.getPort() : 80;

            // 与目标服务器建立连接
            try (Socket targetSocket = new Socket(targetHost, targetPort)) {
                targetSocket.setSoTimeout(30000);

                OutputStream targetOut = targetSocket.getOutputStream();
                InputStream targetIn = targetSocket.getInputStream();

                // 重新构造请求行：使用相对路径
                String pathAndQuery = url.getFile().isEmpty() ? "/" : url.getFile();
                String newRequestLine = method + " " + pathAndQuery + " " + httpVersion + "\r\n";
                targetOut.write(newRequestLine.getBytes());

                // 拷贝并修改请求头
                for (Map.Entry<String, String> entry : headers.entrySet()) {
                    String name = entry.getKey();
                    String value = entry.getValue();

                    if ("Proxy-Connection".equalsIgnoreCase(name)) {
                        // 丢弃 Proxy-Connection
                        continue;
                    }

                    if ("Host".equalsIgnoreCase(name)) {
                        // 如果强制后端域名，则覆盖 Host
                        if (FORCE_TARGET_HOST != null) {
                            value = FORCE_TARGET_HOST;
                        }
                    }

                    // 在这里对 header 做你的自定义修改
                    // 示例：增加或修改自定义头
                    // if ("User-Agent".equalsIgnoreCase(name)) { value = "My-Custom-UA"; }

                    String headerLine = name + ": " + value + "\r\n";
                    targetOut.write(headerLine.getBytes());
                }

                // 追加你自己的自定义头（统一加）
                String customHeader = "X-From-Proxy: true\r\n";
                targetOut.write(customHeader.getBytes());

                // 头结束
                targetOut.write("\r\n".getBytes());

                // 写入请求体
                if (body != null && body.length > 0) {
                    targetOut.write(body);
                }
                targetOut.flush();

                // 把目标服务器响应原样转发给浏览器
                relayResponse(targetIn, clientWriter);
            }

        } catch (IOException e) {
            // 简单打印错误，实际可以换成日志
            e.printStackTrace();
        }
    }

    /**
     * 使用自签证书做 HTTPS MITM：
     * - 与客户端建立 TLS（服务器端）
     * - 与目标服务器建立 TLS（客户端）
     * - 解密 HTTP，修改头，再转发
     *
     * 为简单起见，这里只处理一个请求/响应，连接关闭。
     */
    private void handleHttpsMitm(String connectLine, Socket clientSocket) throws IOException {
        // 示例：CONNECT www.example.com:443 HTTP/1.1
        StringTokenizer tokenizer = new StringTokenizer(connectLine);
        tokenizer.nextToken(); // CONNECT
        String hostPort = tokenizer.nextToken();
        String httpVersion = tokenizer.nextToken();

        String[] hp = hostPort.split(":");
        String host = hp[0];
        int port = hp.length > 1 ? Integer.parseInt(hp[1]) : 443;

        // 告诉客户端“连接已建立”
        OutputStream rawOut = clientSocket.getOutputStream();
        String response = httpVersion + " 200 Connection Established\r\n\r\n";
        rawOut.write(response.getBytes());
        rawOut.flush();

        try {
            // 与客户端建立 TLS（服务器端）
            SSLSocket sslClient = (SSLSocket) SERVER_SSL_CONTEXT.getSocketFactory()
                    .createSocket(clientSocket, host, port, true);
            sslClient.setUseClientMode(false);
            sslClient.startHandshake();

            BufferedReader clientReader =
                    new BufferedReader(new InputStreamReader(sslClient.getInputStream()));
            BufferedOutputStream clientWriter =
                    new BufferedOutputStream(sslClient.getOutputStream());

            // 读取真正的 HTTPS 内部 HTTP 请求
            String requestLine = clientReader.readLine();
            if (requestLine == null || requestLine.isEmpty()) {
                return;
            }

            StringTokenizer reqTok = new StringTokenizer(requestLine);
            String method = reqTok.nextToken();
            String path = reqTok.nextToken(); // /path?query
            String version = reqTok.nextToken();

            // 读取请求头
            Map<String, String> headers = new LinkedHashMap<>();
            String line;
            int contentLength = 0;
            while ((line = clientReader.readLine()) != null && !line.isEmpty()) {
                int idx = line.indexOf(':');
                if (idx > 0) {
                    String name = line.substring(0, idx).trim();
                    String value = line.substring(idx + 1).trim();
                    headers.put(name, value);
                    if ("Content-Length".equalsIgnoreCase(name)) {
                        try {
                            contentLength = Integer.parseInt(value);
                        } catch (NumberFormatException ignored) {
                        }
                    }
                }
            }

            // 读取请求体
            byte[] body = null;
            if (contentLength > 0) {
                body = sslClient.getInputStream().readNBytes(contentLength);
            }

            String targetHost = FORCE_TARGET_HOST != null ? FORCE_TARGET_HOST : host;
            int targetPort = port > 0 ? port : 443;

            // 与目标服务器建立 TLS 连接（客户端）
            SSLSocket targetSsl = (SSLSocket) CLIENT_SSL_CONTEXT.getSocketFactory()
                    .createSocket(targetHost, targetPort);
            targetSsl.setUseClientMode(true);
            targetSsl.startHandshake();

            OutputStream targetOut = targetSsl.getOutputStream();
            InputStream targetIn = targetSsl.getInputStream();

            // 构造请求行（相对路径）
            String newRequestLine = method + " " + path + " " + version + "\r\n";
            targetOut.write(newRequestLine.getBytes());

            // 拷贝并修改请求头
            for (Map.Entry<String, String> entry : headers.entrySet()) {
                String name = entry.getKey();
                String value = entry.getValue();

                if ("Proxy-Connection".equalsIgnoreCase(name)) {
                    continue;
                }

                if ("Host".equalsIgnoreCase(name)) {
                    if (FORCE_TARGET_HOST != null) {
                        value = FORCE_TARGET_HOST;
                    }
                }

                // 在这里对 header 做你的自定义修改
                // 例如：
                // if ("User-Agent".equalsIgnoreCase(name)) { value = "My-Custom-UA"; }

                String headerLine = name + ": " + value + "\r\n";
                targetOut.write(headerLine.getBytes());
            }

            // 统一追加自定义头
            String customHeader = "X-From-Proxy: true\r\n";
            targetOut.write(customHeader.getBytes());

            // 结束头
            targetOut.write("\r\n".getBytes());

            // 写入请求体
            if (body != null && body.length > 0) {
                targetOut.write(body);
            }
            targetOut.flush();

            // 把目标服务器响应转发给客户端（此时在 TLS 内部，仍然是明文 HTTP）
            relayResponse(targetIn, clientWriter);

            targetSsl.close();
            sslClient.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void initSslContexts() throws IOException {
        try {
            // 服务端 SSLContext：使用我们自己的证书（PKCS12）
            KeyStore ks = KeyStore.getInstance("PKCS12");
            try (InputStream is = new FileInputStream(KEYSTORE_PATH)) {
                ks.load(is, KEYSTORE_PASSWORD.toCharArray());
            }
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(ks, KEYSTORE_PASSWORD.toCharArray());

            SSLContext serverCtx = SSLContext.getInstance("TLS");
            serverCtx.init(kmf.getKeyManagers(), null, null);
            SERVER_SSL_CONTEXT = serverCtx;

            // 客户端 SSLContext：使用系统默认信任（访问业务服务器）
            SSLContext clientCtx = SSLContext.getInstance("TLS");
            clientCtx.init(null, null, null);
            CLIENT_SSL_CONTEXT = clientCtx;
        } catch (GeneralSecurityException e) {
            throw new IOException("初始化 SSL 上下文失败，请检查 " + KEYSTORE_PATH + " 是否存在且密码正确", e);
        }
    }

    private void sendBadRequest(BufferedOutputStream clientWriter, String message) throws IOException {
        String body = "Bad Request: " + message;
        String response =
                "HTTP/1.1 400 Bad Request\r\n" +
                        "Content-Type: text/plain; charset=utf-8\r\n" +
                        "Content-Length: " + body.getBytes().length + "\r\n" +
                        "\r\n" +
                        body;
        clientWriter.write(response.getBytes());
        clientWriter.flush();
    }

    private void relayResponse(InputStream targetIn, BufferedOutputStream clientWriter) throws IOException {
        byte[] buffer = new byte[8192];
        int len;
        while ((len = targetIn.read(buffer)) != -1) {
            clientWriter.write(buffer, 0, len);
            clientWriter.flush();
        }
    }

    public static void main(String[] args) throws IOException {
        int port = 8888;
        if (args.length > 0) {
            port = Integer.parseInt(args[0]);
        }
        HttpProxyServer server = new HttpProxyServer(port);
        server.start();
    }
}

