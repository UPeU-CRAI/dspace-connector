package com.identicum.connectors;

import com.evolveum.polygon.rest.AbstractRestConfiguration;
import org.identityconnectors.framework.common.exceptions.ConnectorIOException;
import org.identityconnectors.common.security.GuardedString;

import java.net.CookieManager;
import java.net.CookiePolicy;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.logging.Logger;

public class AuthManager {

    private static final Logger LOG = Logger.getLogger(AuthManager.class.getName());
    private final AbstractRestConfiguration config;
    private String csrfToken;
    private String tokenName;
    private String tokenValue;
    private final HttpClient client;

    public AuthManager(AbstractRestConfiguration config) {
        this.config = config;
        this.client = HttpClient.newBuilder()
                .cookieHandler(new CookieManager(null, CookiePolicy.ACCEPT_ALL))
                .build();
    }

    public void authenticate() {
        try {
            setTokenName("Bearer");

            // Log para capturar el username antes de iniciar la autenticación
            LOG.info("Starting authentication with username: " + config.getUsername());

            obtainCsrfToken();
            LOG.info("CSRF token obtained successfully.");

            obtainTokenValue();
            LOG.info("JWT token obtained successfully.");
        } catch (Exception e) {
            LOG.severe("Authentication failed: " + e.getMessage());
            throw new ConnectorIOException("Authentication failed: " + e.getMessage(), e);
        }
    }

    private void obtainCsrfToken() throws Exception {
        String url = config.getServiceAddress().replaceAll("/$", "") + "/server/api/authn/status";
        LOG.info("Sending request to obtain CSRF token from: " + url);

        HttpRequest request = HttpRequest.newBuilder()
                .uri(new URI(url))
                .GET()
                .build();

        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

        LOG.info("Response status code for CSRF token request: " + response.statusCode());

        if (response.headers().firstValue("Set-Cookie").isPresent()) {
            String cookieHeader = response.headers().firstValue("Set-Cookie").get();
            LOG.info("Cookie header received: " + cookieHeader);
            csrfToken = extractCsrfTokenFromCookie(cookieHeader);
            LOG.info("CSRF Token obtained: " + csrfToken);
        } else {
            LOG.severe("Failed to obtain CSRF token.");
            throw new ConnectorIOException("Failed to obtain CSRF token.");
        }
    }

    private void obtainTokenValue() throws Exception {
        String url = config.getServiceAddress().replaceAll("/$", "") + "/server/api/authn/login";
        LOG.info("Sending POST request to obtain JWT token from: " + url);

        // Extraer la contraseña de GuardedString
        final StringBuilder passwordBuilder = new StringBuilder();
        config.getPassword().access(clearChars -> passwordBuilder.append(new String(clearChars)));
        String password = passwordBuilder.toString();

        // Log para verificar el password
        LOG.info("Extracted password length: " + password.length());

        // Crear el cuerpo de la solicitud con el usuario y la contraseña
        String body = "user=" + URLEncoder.encode(config.getUsername(), StandardCharsets.UTF_8) +
                "&password=" + URLEncoder.encode(password, StandardCharsets.UTF_8);
        LOG.info("Request body: " + body);

        HttpRequest request = HttpRequest.newBuilder()
                .uri(new URI(url))
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("X-XSRF-TOKEN", csrfToken)
                .build();

        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

        LOG.info("Response status code for JWT token request: " + response.statusCode());
        LOG.info("Response body: " + response.body());

        if (response.headers().firstValue("Authorization").isPresent()) {
            tokenValue = response.headers().firstValue("Authorization").get().replace(getTokenName() + " ", "");
            LOG.info("Token Value obtained: " + tokenValue);
        } else {
            LOG.severe("Authorization header not found in response.");
            throw new ConnectorIOException("Failed to obtain token value.");
        }
    }

    public boolean isAuthenticated() {
        return tokenValue != null && !tokenValue.isEmpty();
    }

    // método getCsrfToken() en la clase AuthManager para devolver el valor del token CSRF y ser usado públicamente en otras clases
    public String getCsrfToken() {
        if (csrfToken == null || csrfToken.isEmpty()) {
            throw new ConnectorIOException("CSRF token is missing. Authentication might have failed.");
        }
        return csrfToken;
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
            LOG.info("Inspecting cookie part: " + part.trim());
            if (part.trim().startsWith("DSPACE-XSRF-COOKIE=")) {
                String csrf = part.split("=")[1];
                LOG.info("Extracted CSRF Token: " + csrf);
                return csrf;
            }
        }

        LOG.severe("CSRF token not found in cookie header.");
        throw new ConnectorIOException("CSRF token not found in cookie header.");
    }
}
