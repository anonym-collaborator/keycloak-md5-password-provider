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

	@Override
	public void close() {
	}

	@Override
	public boolean policyCheck(PasswordPolicy policy, PasswordCredentialModel credential) {
		return this.providerId.equals(credential.getPasswordCredentialData().getAlgorithm());
	}

	@Override
	public PasswordCredentialModel encodedCredential(String rawPassword, int iterations) {
		String encodedPassword = this.encode(rawPassword, iterations);
		return PasswordCredentialModel.createFromValues(this.providerId, new byte[0], iterations, encodedPassword);
	}

	@Override
	public boolean verify(String rawPassword, PasswordCredentialModel credential) {
		String encodedPassword = this.encode(rawPassword, credential.getPasswordCredentialData().getHashIterations());
		String hash = credential.getPasswordSecretData().getValue();
		return encodedPassword.equalsIgnoreCase(hash);
	}

	@Override
	public String encode(String rawPassword, int iterations) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] digest = md.digest(rawPassword.getBytes(StandardCharsets.US_ASCII));
            return bytesToHex(digest).toLowerCase();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("MD5 Algorithm not found", e);
        }
	}

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
