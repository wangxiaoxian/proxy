package com.example.proxy;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Deque;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class ProxyServer {
    private static final Logger log = LoggerFactory.getLogger(ProxyServer.class);

    private final ProxyConfig config;
    private final HeaderRewriteEngine rewriteEngine;
    private final CertificateAuthority certificateAuthority;
    private final Map<Integer, ProxyConfig.ProfileConfig> profileByPort = new HashMap<>();
    private final ExecutorService workerPool;
    private final Deque<RequestLogEntry> recentRequests = new ArrayDeque<>();

    public ProxyServer(ProxyConfig config, HeaderRewriteEngine rewriteEngine, CertificateAuthority certificateAuthority) {
        this.config = config;
        this.rewriteEngine = rewriteEngine;
        this.certificateAuthority = certificateAuthority;
        this.workerPool = Executors.newFixedThreadPool(config.server.maxWorkerThreads);
        for (ProxyConfig.ListenerConfig listener : config.server.listeners) {
            profileByPort.put(listener.port, findProfile(listener.profileId));
        }
    }

    public void start() throws IOException {
        startAdminServer();
        for (ProxyConfig.ListenerConfig listener : config.server.listeners) {
            startListener(listener.port);
        }
    }

    private ProxyConfig.ProfileConfig findProfile(String profileId) {
        return config.profiles.stream()
                .filter(profile -> profile.id.equals(profileId))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("Unknown profile: " + profileId));
    }

    private void startListener(int port) {
        Thread thread = new Thread(() -> listen(port), "proxy-listener-" + port);
        thread.setDaemon(false);
        thread.start();
    }

    private void listen(int port) {
        try (var serverSocket = new java.net.ServerSocket(port)) {
            log.info("Proxy listener started on port {}", port);
            while (true) {
                Socket clientSocket = serverSocket.accept();
                clientSocket.setSoTimeout(config.server.socketTimeoutMillis);
                workerPool.submit(() -> handleClient(clientSocket, port));
            }
        } catch (IOException e) {
            throw new IllegalStateException("Failed to bind listener on port " + port, e);
        }
    }

    private void handleClient(Socket clientSocket, int listenerPort) {
        ProxyConfig.ProfileConfig profile = profileByPort.get(listenerPort);
        try (clientSocket) {
            BufferedInputStream inputStream = new BufferedInputStream(clientSocket.getInputStream());
            BufferedOutputStream outputStream = new BufferedOutputStream(clientSocket.getOutputStream());
            ParsedHttpRequest firstRequest = HttpMessageReader.readRequest(inputStream);
            if (firstRequest == null) {
                return;
            }
            if ("CONNECT".equalsIgnoreCase(firstRequest.method)) {
                handleConnectTunnel(clientSocket, inputStream, outputStream, firstRequest, profile);
                return;
            }
            processHttpSession(inputStream, outputStream, firstRequest, profile, "http");
        } catch (Exception e) {
            log.warn("Client handling failed on port {}: {}", listenerPort, e.getMessage(), e);
        }
    }

    private void handleConnectTunnel(Socket clientSocket,
                                     BufferedInputStream rawInput,
                                     BufferedOutputStream rawOutput,
                                     ParsedHttpRequest connectRequest,
                                     ProxyConfig.ProfileConfig profile) throws Exception {
        String authority = connectRequest.target;
        String[] hostPort = authority.split(":", 2);
        String host = hostPort[0];
        int port = hostPort.length > 1 ? Integer.parseInt(hostPort[1]) : 443;

        rawOutput.write((connectRequest.version + " 200 Connection Established\r\n\r\n")
                .getBytes(StandardCharsets.ISO_8859_1));
        rawOutput.flush();

        SSLContext serverSslContext = certificateAuthority.serverSslContextForHost(host);
        try (SSLSocket clientSslSocket = (SSLSocket) serverSslContext.getSocketFactory()
                .createSocket(clientSocket, host, port, true)) {
            clientSslSocket.setUseClientMode(false);
            clientSslSocket.setSoTimeout(config.server.socketTimeoutMillis);
            clientSslSocket.startHandshake();

            BufferedInputStream mitmInput = new BufferedInputStream(clientSslSocket.getInputStream());
            BufferedOutputStream mitmOutput = new BufferedOutputStream(clientSslSocket.getOutputStream());
            processHttpSession(mitmInput, mitmOutput, null, profile, "https");
        }
    }

    private void processHttpSession(InputStream clientInput,
                                    OutputStream clientOutput,
                                    ParsedHttpRequest firstRequest,
                                    ProxyConfig.ProfileConfig profile,
                                    String scheme) throws IOException {
        ParsedHttpRequest request = firstRequest;
        while (true) {
            if (request == null) {
                request = HttpMessageReader.readRequest(clientInput);
            }
            if (request == null) {
                return;
            }
            RequestContext context = resolveTarget(request, scheme);
            List<String> applied = rewriteEngine.apply(request, context.host, profile);
            forwardSingleRequest(request, clientOutput, profile, context, applied, scheme);
            if (shouldClose(request)) {
                return;
            }
            request = null;
        }
    }

    private RequestContext resolveTarget(ParsedHttpRequest request, String scheme) throws IOException {
        if ("https".equalsIgnoreCase(scheme)) {
            String hostHeader = request.header("Host");
            if (hostHeader == null || hostHeader.isBlank()) {
                throw new IOException("Missing Host header");
            }
            return new RequestContext("https", hostFromAuthority(hostHeader), portFromAuthority(hostHeader, 443));
        }
        if (request.target.startsWith("http://") || request.target.startsWith("https://")) {
            URI uri = URI.create(request.target);
            int port = uri.getPort() > 0 ? uri.getPort() : ("https".equalsIgnoreCase(uri.getScheme()) ? 443 : 80);
            return new RequestContext(uri.getScheme(), uri.getHost(), port);
        }
        String hostHeader = request.header("Host");
        if (hostHeader == null || hostHeader.isBlank()) {
            throw new IOException("Missing Host header");
        }
        return new RequestContext("http", hostFromAuthority(hostHeader), portFromAuthority(hostHeader, 80));
    }

    private void forwardSingleRequest(ParsedHttpRequest request,
                                      OutputStream clientOutput,
                                      ProxyConfig.ProfileConfig profile,
                                      RequestContext context,
                                      List<String> applied,
                                      String scheme) throws IOException {
        long startNanos = System.nanoTime();
        String requestId = UUID.randomUUID().toString();

        request.removeHeader("Proxy-Connection");
        request.setHeader("Connection", "close");
        if (!request.hasHeader("Host")) {
            request.setHeader("Host", context.host + (context.includePortInHostHeader() ? ":" + context.port : ""));
        }

        try (Socket upstream = createUpstreamSocket(context);
             BufferedOutputStream upstreamOut = new BufferedOutputStream(upstream.getOutputStream());
             BufferedInputStream upstreamIn = new BufferedInputStream(upstream.getInputStream())) {
            String target = request.relativeTarget(context.scheme, context.host);
            upstreamOut.write((request.method + " " + target + " " + request.version + "\r\n")
                    .getBytes(StandardCharsets.ISO_8859_1));
            for (Map.Entry<String, String> header : request.headers.entrySet()) {
                upstreamOut.write((header.getKey() + ": " + header.getValue() + "\r\n")
                        .getBytes(StandardCharsets.ISO_8859_1));
            }
            upstreamOut.write("\r\n".getBytes(StandardCharsets.ISO_8859_1));
            if (request.body.length > 0) {
                upstreamOut.write(request.body);
            }
            upstreamOut.flush();

            relay(upstreamIn, clientOutput);

            recordRequest(new RequestLogEntry(
                    requestId,
                    Instant.now().toString(),
                    profile.id,
                    scheme,
                    context.host,
                    context.port,
                    request.method,
                    target,
                    applied,
                    0,
                    elapsedMillis(startNanos),
                    "https".equalsIgnoreCase(scheme),
                    null,
                    redactHeaders(request.headers)
            ));
        } catch (IOException e) {
            recordRequest(new RequestLogEntry(
                    requestId,
                    Instant.now().toString(),
                    profile.id,
                    scheme,
                    context.host,
                    context.port,
                    request.method,
                    request.target,
                    applied,
                    0,
                    elapsedMillis(startNanos),
                    "https".equalsIgnoreCase(scheme),
                    e.getMessage(),
                    redactHeaders(request.headers)
            ));
            throw e;
        }
    }

    private Socket createUpstreamSocket(RequestContext context) throws IOException {
        if ("https".equalsIgnoreCase(context.scheme)) {
            try {
                SSLSocket sslSocket = (SSLSocket) SSLContext.getDefault().getSocketFactory()
                        .createSocket(context.host, context.port);
                sslSocket.setUseClientMode(true);
                sslSocket.setSoTimeout(config.server.socketTimeoutMillis);
                sslSocket.startHandshake();
                return sslSocket;
            } catch (Exception e) {
                throw new IOException("Failed to open TLS upstream connection", e);
            }
        }
        Socket socket = new Socket();
        socket.connect(new InetSocketAddress(context.host, context.port), config.server.connectTimeoutMillis);
        socket.setSoTimeout(config.server.socketTimeoutMillis);
        return socket;
    }

    private boolean shouldClose(ParsedHttpRequest request) {
        String connection = request.header("Connection");
        return connection != null && "close".equalsIgnoreCase(connection);
    }

    private void relay(InputStream upstreamIn, OutputStream clientOutput) throws IOException {
        byte[] buffer = new byte[8192];
        int read;
        while ((read = upstreamIn.read(buffer)) != -1) {
            clientOutput.write(buffer, 0, read);
        }
        clientOutput.flush();
    }

    private String hostFromAuthority(String authority) {
        int separator = authority.lastIndexOf(':');
        if (separator > 0 && authority.indexOf(']') < separator) {
            return authority.substring(0, separator);
        }
        return authority;
    }

    private int portFromAuthority(String authority, int defaultPort) {
        int separator = authority.lastIndexOf(':');
        if (separator > 0 && authority.indexOf(']') < separator) {
            return Integer.parseInt(authority.substring(separator + 1));
        }
        return defaultPort;
    }

    private static long elapsedMillis(long startNanos) {
        return (System.nanoTime() - startNanos) / 1_000_000;
    }

    private Map<String, String> redactHeaders(Map<String, String> headers) {
        Map<String, String> redacted = new HashMap<>();
        for (Map.Entry<String, String> entry : headers.entrySet()) {
            String lower = entry.getKey().toLowerCase(Locale.ROOT);
            if (config.rewrite.redactHeaders.contains(lower)) {
                redacted.put(entry.getKey(), "<redacted>");
            } else {
                redacted.put(entry.getKey(), entry.getValue());
            }
        }
        return redacted;
    }

    private synchronized void recordRequest(RequestLogEntry entry) {
        while (recentRequests.size() >= 100) {
            recentRequests.removeFirst();
        }
        recentRequests.addLast(entry);
        log.info("{} {}://{}:{}{} profile={} rewrites={} error={}",
                entry.method,
                entry.scheme,
                entry.host,
                entry.port,
                entry.path,
                entry.profileId,
                entry.appliedRules,
                entry.errorReason);
    }

    private void startAdminServer() throws IOException {
        if (!config.admin.enabled) {
            return;
        }
        HttpServer adminServer = HttpServer.create(new InetSocketAddress(config.admin.host, config.admin.port), 0);
        adminServer.createContext("/_admin/health", this::handleHealth);
        adminServer.createContext("/_admin/config", this::handleConfig);
        adminServer.createContext("/_admin/recent-requests", this::handleRecentRequests);
        adminServer.setExecutor(Executors.newSingleThreadExecutor());
        adminServer.start();
        log.info("Admin server started on {}:{}", config.admin.host, config.admin.port);
    }

    private void handleHealth(HttpExchange exchange) throws IOException {
        writeJson(exchange, 200, "{\"status\":\"ok\"}");
    }

    private void handleConfig(HttpExchange exchange) throws IOException {
        StringBuilder builder = new StringBuilder();
        builder.append("{\"listeners\":[");
        for (int i = 0; i < config.server.listeners.size(); i++) {
            ProxyConfig.ListenerConfig listener = config.server.listeners.get(i);
            if (i > 0) {
                builder.append(',');
            }
            builder.append("{\"port\":").append(listener.port)
                    .append(",\"profileId\":\"").append(listener.profileId).append("\"}");
        }
        builder.append("],\"caCertPath\":\"").append(config.tls.ca.certPath).append("\"}");
        writeJson(exchange, 200, builder.toString());
    }

    private synchronized void handleRecentRequests(HttpExchange exchange) throws IOException {
        StringBuilder builder = new StringBuilder("[");
        int index = 0;
        for (RequestLogEntry entry : recentRequests) {
            if (index++ > 0) {
                builder.append(',');
            }
            builder.append(entry.toJson());
        }
        builder.append(']');
        writeJson(exchange, 200, builder.toString());
    }

    private void writeJson(HttpExchange exchange, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream responseBody = exchange.getResponseBody()) {
            responseBody.write(bytes);
        }
    }

    private record RequestContext(String scheme, String host, int port) {
        private boolean includePortInHostHeader() {
            return ("http".equalsIgnoreCase(scheme) && port != 80)
                    || ("https".equalsIgnoreCase(scheme) && port != 443);
        }
    }

    private record RequestLogEntry(String requestId,
                                   String timestamp,
                                   String profileId,
                                   String scheme,
                                   String host,
                                   int port,
                                   String method,
                                   String path,
                                   List<String> appliedRules,
                                   int statusCode,
                                   long durationMs,
                                   boolean tlsMitm,
                                   String errorReason,
                                   Map<String, String> headers) {
        private String toJson() {
            return "{\"requestId\":\"" + json(requestId) +
                    "\",\"timestamp\":\"" + json(timestamp) +
                    "\",\"profileId\":\"" + json(profileId) +
                    "\",\"scheme\":\"" + json(scheme) +
                    "\",\"host\":\"" + json(host) +
                    "\",\"port\":" + port +
                    ",\"method\":\"" + json(method) +
                    "\",\"path\":\"" + json(path) +
                    "\",\"durationMs\":" + durationMs +
                    ",\"tlsMitm\":" + tlsMitm +
                    ",\"errorReason\":\"" + json(errorReason == null ? "" : errorReason) +
                    "\",\"headers\":\"" + json(Base64.getEncoder().encodeToString(headers.toString().getBytes(StandardCharsets.UTF_8))) +
                    "\"}";
        }

        private static String json(String value) {
            return value.replace("\\", "\\\\").replace("\"", "\\\"");
        }
    }
}
