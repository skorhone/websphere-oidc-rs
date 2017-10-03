package fi.kela.auth.was.oic;

import java.util.Properties;

public class Configuration {
	private String secretKey;
	private String acceptedIssuer;
	private String realm;
	private String groupClaim;

	public Configuration(Properties properties) {
		this.secretKey = getProperty(properties, "secretKey");
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

	public String getSecretKey() {
		return secretKey;
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
