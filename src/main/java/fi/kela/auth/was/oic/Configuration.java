package fi.kela.auth.was.oic;

import java.util.Properties;

/**
 * Configuration properties for TAI
 * 
 * @author l007gat
 *
 */
public class Configuration {
	public enum SA { RS256, HS256 } 
	private SA signatureAlgorithm;
	private String publicKey;
	private String secretKey;
	private String acceptedIssuer;
	private String realm;
	private String groupClaim;

	public Configuration(Properties properties) {
		this.signatureAlgorithm = SA.valueOf(getProperty(properties, "signatureAlgorithm"));
		if (signatureAlgorithm == SA.RS256) {
			this.publicKey = getProperty(properties, "publicKey");
		} else {
			this.secretKey = getProperty(properties, "secretKey");
		}
		this.acceptedIssuer = getProperty(properties, "acceptedIssuer");
		this.realm = getProperty(properties, "realm");
		this.groupClaim = getProperty(properties, "groupClaim");
	}

	private String getProperty(Properties properties, String propertyName) {
		String value = properties.getProperty(propertyName);
		if (value == null) {
			throw new IllegalArgumentException("Required property " + propertyName + " was not set!");
		}
		return value;
	}

	public SA getSignatureAlgorithm() {
		return signatureAlgorithm;
	}

	public String getSecretKey() {
		return secretKey;
	}
	
	public String getPublicKey() {
		return publicKey;
	}

	public String getAcceptedIssuer() {
		return acceptedIssuer;
	}

	public String getRealm() {
		return realm;
	}

	public String getGroupClaim() {
		return groupClaim;
	}
}
