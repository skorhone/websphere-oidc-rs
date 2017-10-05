package fi.kela.auth.was.oic;

import java.io.UnsupportedEncodingException;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Hashtable;
import java.util.List;
import java.util.Properties;

import javax.security.auth.Subject;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.ibm.websphere.security.WebTrustAssociationException;
import com.ibm.websphere.security.WebTrustAssociationFailedException;
import com.ibm.wsspi.security.tai.TAIResult;
import com.ibm.wsspi.security.tai.TrustAssociationInterceptor;
import com.ibm.wsspi.security.token.AttributeNameConstants;

import fi.kela.auth.was.oic.Configuration.SA;

public class ResourceServerTAI implements TrustAssociationInterceptor {
	private static final String TOKEN_PREFIX = "Bearer ";
	private static final String AUTH_HEADER = "Authorization";
	private Configuration configuration;

	@Override
	public int initialize(Properties properties) throws WebTrustAssociationFailedException {
		configuration = new Configuration(properties);
		return 0;
	}

	@Override
	public void cleanup() {
	}

	@Override
	public String getType() {
		return null;
	}

	@Override
	public String getVersion() {
		return "1.0";
	}

	@Override
	public boolean isTargetInterceptor(HttpServletRequest req) throws WebTrustAssociationException {
		return containsTokenAuthorizationHeader(req);
	}

	private boolean containsTokenAuthorizationHeader(HttpServletRequest req) {
		String auth = req.getHeader(AUTH_HEADER);
		if (auth != null && auth.startsWith(TOKEN_PREFIX)) {
			return true;
		}
		return false;
	}

	@Override
	public TAIResult negotiateValidateandEstablishTrust(HttpServletRequest req, HttpServletResponse res)
			throws WebTrustAssociationFailedException {
		String auth = req.getHeader(AUTH_HEADER);
		String token = auth.substring(TOKEN_PREFIX.length());

		DecodedJWT jwt = validateToken(token);
		Subject subject = createSubject(jwt);

		return TAIResult.create(HttpServletResponse.SC_OK, "ignored", subject);
	}

	private DecodedJWT validateToken(String token) throws WebTrustAssociationFailedException {
		try {
			Algorithm algorithm = getSignatureAlgorithm();
			JWTVerifier verifier = JWT.require(algorithm).withIssuer(configuration.getAcceptedIssuer()).build();
			return verifier.verify(token);
		} catch (Exception exception) {
			throw new WebTrustAssociationFailedException(exception.getMessage());
		}
	}

	private Algorithm getSignatureAlgorithm() {
		Algorithm algorithm;
		if (configuration.getSignatureAlgorithm() == SA.RS256) {
			algorithm = getRS256SignatureAlgorithm();
		} else {
			algorithm = getHS256SignatureAlgorithm();
		}
		return algorithm;
	}

	private Algorithm getHS256SignatureAlgorithm() {
		try {
			return Algorithm.HMAC256(configuration.getSecretKey());
		} catch (UnsupportedEncodingException exception) {
			throw new IllegalStateException("Could not initialize HS256 algorithm", exception);
		}
	}

	private Algorithm getRS256SignatureAlgorithm() {
		try {
			KeySpec publicKeySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(configuration.getPublicKey()));
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			RSAPublicKey publicKey = (RSAPublicKey) keyFactory.generatePublic(publicKeySpec);
			return Algorithm.RSA256(publicKey, null);
		} catch (Exception exception) {
			throw new IllegalStateException("Could not initialize RS256 algorithm, exception");
		}
	}

	private Subject createSubject(DecodedJWT token) {
		List<String> groups = getGroups(token);

		Hashtable<String, Object> properties = new Hashtable<String, Object>();
		properties.put(AttributeNameConstants.WSCREDENTIAL_REALM, configuration.getRealm());
		properties.put(AttributeNameConstants.WSCREDENTIAL_UNIQUEID, token.getSubject());
		properties.put(AttributeNameConstants.WSCREDENTIAL_SECURITYNAME, token.getSubject());
		properties.put(AttributeNameConstants.WSCREDENTIAL_GROUPS, groups);

		Subject subject = new Subject();
		subject.getPublicCredentials().add(properties);

		return subject;
	}

	private List<String> getGroups(DecodedJWT token) {
		return token.getClaim(configuration.getGroupClaim()).asList(String.class);
	}
}
