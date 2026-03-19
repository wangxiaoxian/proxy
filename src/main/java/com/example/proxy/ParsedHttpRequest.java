package com.example.proxy;

import java.net.URI;
import java.util.LinkedHashMap;
import java.util.Map;

public class ParsedHttpRequest {
    public String method;
    public String target;
    public String version;
    public LinkedHashMap<String, String> headers = new LinkedHashMap<>();
    public byte[] body = new byte[0];
    public boolean chunked;

    public String header(String name) {
        for (Map.Entry<String, String> entry : headers.entrySet()) {
            if (entry.getKey().equalsIgnoreCase(name)) {
                return entry.getValue();
            }
        }
        return null;
    }

    public void setHeader(String name, String value) {
        String existingKey = null;
        for (String key : headers.keySet()) {
            if (key.equalsIgnoreCase(name)) {
                existingKey = key;
                break;
            }
        }
        if (existingKey != null) {
            headers.remove(existingKey);
        }
        headers.put(name, value);
    }

    public void removeHeader(String name) {
        String existingKey = null;
        for (String key : headers.keySet()) {
            if (key.equalsIgnoreCase(name)) {
                existingKey = key;
                break;
            }
        }
        if (existingKey != null) {
            headers.remove(existingKey);
        }
    }

    public boolean hasHeader(String name) {
        return header(name) != null;
    }

    public String relativeTarget(String defaultScheme, String fallbackHost) {
        if (target.startsWith("http://") || target.startsWith("https://")) {
            URI uri = URI.create(target);
            String path = uri.getRawPath();
            if (path == null || path.isEmpty()) {
                path = "/";
            }
            String query = uri.getRawQuery();
            return query == null ? path : path + "?" + query;
        }
        if (target.isEmpty()) {
            return "/";
        }
        if (target.startsWith("/")) {
            return target;
        }
        return URI.create(defaultScheme + "://" + fallbackHost + target).getRawPath();
    }
}
