package fi.kela.auth.was.oidc;

import java.util.Properties;

/**
 * Configuration properties for TAI
 * 
 * @author l007gat
 *
 */
public class Configuration {
	public static final String SIGNATURE_ALGORITHM = "signatureAlgorithm";
	public static final String PUBLIC_KEY = "publicKey";
	public static final String SECRET_KEY = "secretKey";
	public static final String REALM = "realm";
	public static final String ACCEPTED_ISSUER = "acceptedIssuer";
	public static final String GROUP_CLAIM = "groupClaim";

	public enum SA {
		RS256, HS256
	}

	private SA signatureAlgorithm;
	private String publicKey;
	private String secretKey;
	private String acceptedIssuer;
	private String realm;
	private String groupClaim;

	private Configuration() {
	}

	public static Configuration from(Properties properties) {
		Configuration configuration = new Configuration();
		configuration.signatureAlgorithm = SA.valueOf(getProperty(properties, SIGNATURE_ALGORITHM));
		if (configuration.signatureAlgorithm == SA.RS256) {
			configuration.publicKey = getProperty(properties, PUBLIC_KEY);
		} else {
			configuration.secretKey = getProperty(properties, SECRET_KEY);
		}
		configuration.acceptedIssuer = getProperty(properties, ACCEPTED_ISSUER);
		configuration.realm = getProperty(properties, REALM);
		configuration.groupClaim = getProperty(properties, GROUP_CLAIM);
		return configuration;
	}

	private static String getProperty(Properties properties, String propertyName) {
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
