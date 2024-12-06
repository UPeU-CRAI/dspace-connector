package com.identicum.connectors;

import com.evolveum.polygon.rest.AbstractRestConfiguration;
import org.identityconnectors.common.security.GuardedString;

public class RestUsersConfiguration extends AbstractRestConfiguration {

    private String tokenName;
    private GuardedString tokenValue;

    public String getTokenName() {
        return tokenName;
    }

    public void setTokenName(String tokenName) {
        this.tokenName = tokenName;
    }

    @Override
    public GuardedString getTokenValue() {
        return tokenValue;
    }

    @Override
    public void setTokenValue(GuardedString tokenValue) {
        this.tokenValue = tokenValue;
    }

    @Override
    public void validate() {
        super.validate();
        if (getServiceAddress() == null || getServiceAddress().isEmpty()) {
            throw new IllegalArgumentException("Service address must be configured.");
        }
        if (getUsername() == null || getUsername().isEmpty()) {
            throw new IllegalArgumentException("Username must be configured.");
        }
        if (getPassword() == null) {
            throw new IllegalArgumentException("Password must be configured.");
        }

        // Verificar si el GuardedString está vacío
        getPassword().access(chars -> {
            if (chars == null || chars.length == 0) {
                throw new IllegalArgumentException("Password must not be empty.");
            }
        });
    }
}
