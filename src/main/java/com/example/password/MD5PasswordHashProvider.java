package com.example.password;

import org.keycloak.credential.hash.PasswordHashProvider;
import org.keycloak.models.PasswordPolicy;
import org.keycloak.models.credential.PasswordCredentialModel;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class MD5PasswordHashProvider implements PasswordHashProvider {

	private final String providerId;

	public MD5PasswordHashProvider(String providerId) {
		this.providerId = providerId;
	}
}
