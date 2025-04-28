package com.example.password;

import org.keycloak.Config;
import org.keycloak.credential.hash.PasswordHashProvider;
import org.keycloak.credential.hash.PasswordHashProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

public class MD5PasswordHashProviderFactory implements PasswordHashProviderFactory {

    public static final String ID = "md5";

    @Override
    public PasswordHashProvider create(KeycloakSession session) {
        return new MD5PasswordHashProvider(getId());
    }

    @Override
    public void init(Config.Scope config) {
    }

    @Override
    public void postInit(org.keycloak.models.KeycloakSessionFactory factory) {
    }

    @Override
    public void close() {
    }

    @Override
    public String getId() {
        return ID;
    }
}