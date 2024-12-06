package com.identicum.connectors;

import com.evolveum.polygon.rest.AbstractRestConfiguration;
import org.identityconnectors.framework.common.exceptions.ConnectorIOException;

import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.URI;
import java.util.logging.Logger;

public class AuthManager {

    private static final Logger LOG = Logger.getLogger(AuthManager.class.getName());
    private final AbstractRestConfiguration config;
    private String csrfToken;
    private String tokenName;
    private String tokenValue;

    public AuthManager(AbstractRestConfiguration config) {
        this.config = config;
    }

    public void authenticate() {
        try {
            setTokenName("Bearer");
            obtainCsrfToken();
            obtainTokenValue();
        } catch (Exception e) {
            throw new ConnectorIOException("Authentication failed: " + e.getMessage(), e);
        }
    }

    private void obtainCsrfToken() throws Exception {
        String url = config.getServiceAddress() + "/server/api/authn/status";
        HttpRequest request = HttpRequest.newBuilder()
                .uri(new URI(url))
                .GET()
                .build();

        HttpClient client = HttpClient.newHttpClient();
        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

        if (response.headers().firstValue("Set-Cookie").isPresent()) {
            String cookieHeader = response.headers().firstValue("Set-Cookie").get();
            csrfToken = extractCsrfTokenFromCookie(cookieHeader);
            LOG.info("CSRF Token obtained: " + csrfToken);
        } else {
            throw new ConnectorIOException("Failed to obtain CSRF token.");
        }
    }

    private void obtainTokenValue() throws Exception {
        String url = config.getServiceAddress() + "/server/api/authn/login";
        String body = "user=" + config.getUsername() + "&password=" + config.getPassword();

        HttpRequest request = HttpRequest.newBuilder()
                .uri(new URI(url))
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("X-XSRF-TOKEN", csrfToken)
                .build();

        HttpClient client = HttpClient.newHttpClient();
        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

        if (response.headers().firstValue("Authorization").isPresent()) {
            tokenValue = response.headers().firstValue("Authorization").get().replace(getTokenName() + " ", "");
            LOG.info("Token Value obtained: " + tokenValue);
        } else {
            throw new ConnectorIOException("Failed to obtain token value.");
        }
    }

    public boolean isAuthenticated() {
        return tokenValue != null && !tokenValue.isEmpty();
    }

    public String getTokenValue() {
        if (!isAuthenticated()) {
            throw new ConnectorIOException("Not authenticated. Token value is missing.");
        }
        return tokenValue;
    }

    public String getTokenName() {
        return this.tokenName;
    }

    public void setTokenName(String tokenName) {
        this.tokenName = tokenName;
    }

    private String extractCsrfTokenFromCookie(String cookieHeader) {
        for (String part : cookieHeader.split(";")) {
            if (part.trim().startsWith("DSPACE-XSRF-COOKIE=")) {
                return part.split("=")[1];
            }
        }
        throw new ConnectorIOException("CSRF token not found in cookie header.");
    }
}
