package com.example.proxy;

import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Locale;

public final class HttpMessageReader {
    private HttpMessageReader() {
    }

    public static ParsedHttpRequest readRequest(InputStream inputStream) throws IOException {
        String requestLine = readLine(inputStream);
        while (requestLine != null && requestLine.isEmpty()) {
            requestLine = readLine(inputStream);
        }
        if (requestLine == null) {
            return null;
        }

        String[] parts = requestLine.split(" ", 3);
        if (parts.length != 3) {
            throw new IOException("Malformed request line: " + requestLine);
        }

        ParsedHttpRequest request = new ParsedHttpRequest();
        request.method = parts[0];
        request.target = parts[1];
        request.version = parts[2];

        String line;
        while ((line = readLine(inputStream)) != null && !line.isEmpty()) {
            int separator = line.indexOf(':');
            if (separator <= 0) {
                continue;
            }
            String name = line.substring(0, separator).trim();
            String value = line.substring(separator + 1).trim();
            request.setHeader(name, value);
        }

        String transferEncoding = lower(request.header("Transfer-Encoding"));
        if ("chunked".equals(transferEncoding)) {
            request.chunked = true;
            request.body = readChunkedBody(inputStream);
            request.removeHeader("Transfer-Encoding");
            request.setHeader("Content-Length", String.valueOf(request.body.length));
        } else {
            int contentLength = parseContentLength(request.header("Content-Length"));
            if (contentLength > 0) {
                request.body = inputStream.readNBytes(contentLength);
                if (request.body.length != contentLength) {
                    throw new EOFException("Unexpected end of stream while reading request body");
                }
            }
        }
        return request;
    }

    private static String lower(String value) {
        return value == null ? null : value.toLowerCase(Locale.ROOT);
    }

    private static int parseContentLength(String value) {
        if (value == null || value.isBlank()) {
            return 0;
        }
        return Integer.parseInt(value);
    }

    private static byte[] readChunkedBody(InputStream inputStream) throws IOException {
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        while (true) {
            String sizeLine = readLine(inputStream);
            if (sizeLine == null) {
                throw new EOFException("Unexpected EOF while reading chunk size");
            }
            int size = Integer.parseInt(sizeLine.split(";", 2)[0].trim(), 16);
            if (size == 0) {
                while (true) {
                    String trailer = readLine(inputStream);
                    if (trailer == null || trailer.isEmpty()) {
                        return body.toByteArray();
                    }
                }
            }
            byte[] chunk = inputStream.readNBytes(size);
            if (chunk.length != size) {
                throw new EOFException("Unexpected EOF while reading chunk data");
            }
            body.write(chunk);
            String endOfChunk = readLine(inputStream);
            if (endOfChunk == null) {
                throw new EOFException("Unexpected EOF after chunk data");
            }
        }
    }

    private static String readLine(InputStream inputStream) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        int previous = -1;
        while (true) {
            int current = inputStream.read();
            if (current == -1) {
                if (buffer.size() == 0 && previous == -1) {
                    return null;
                }
                break;
            }
            if (previous == '\r' && current == '\n') {
                buffer.write('\r');
                break;
            }
            if (previous != -1) {
                buffer.write(previous);
            }
            previous = current;
        }
        byte[] raw = buffer.toByteArray();
        int length = raw.length;
        if (length > 0 && raw[length - 1] == '\r') {
            length -= 1;
        }
        return new String(raw, 0, length, StandardCharsets.ISO_8859_1);
    }
}
