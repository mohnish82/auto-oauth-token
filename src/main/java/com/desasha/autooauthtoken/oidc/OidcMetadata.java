package com.desasha.autooauthtoken.oidc;

import java.security.interfaces.RSAPublicKey;
import java.util.HashMap;
import java.util.Map;

import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;

public class OidcMetadata {

	private OIDCProviderMetadata providerMetadata;
	private Map<String,RSAPublicKey> signatureKeys;

	public OidcMetadata(OIDCProviderMetadata metadata) {
		this.providerMetadata = metadata;
		this.signatureKeys = new HashMap<String, RSAPublicKey>(2);
	}

	public OIDCProviderMetadata getProviderMetadata() {
		return providerMetadata;
	}

	public RSAPublicKey getSignatureKey(String keyId) {
		return signatureKeys.get(keyId);
	}

	public void addSignatureKeys(String keyId, RSAPublicKey key) {
		signatureKeys.put(keyId, key);
	}
}
