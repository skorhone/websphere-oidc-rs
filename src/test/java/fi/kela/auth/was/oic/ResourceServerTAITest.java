package fi.kela.auth.was.oic;

import static org.easymock.EasyMock.expect;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;

import java.util.Arrays;
import java.util.Date;
import java.util.Hashtable;
import java.util.Properties;
import java.util.concurrent.TimeUnit;

import javax.security.auth.Subject;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.easymock.EasyMockSupport;
import org.junit.Before;
import org.junit.Test;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.InvalidClaimException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.ibm.wsspi.security.token.AttributeNameConstants;

public class ResourceServerTAITest extends EasyMockSupport {
	private static final String SUBJECT = "TestUser";
	private static final String ISSUER = "Test";
	private static final String GROUP_ID = "groupId";
	private static final String[] GROUPS = { "First", "Second" };
	private static final String REALM = "testrealm";
	public static final String TEST_SECRET = "E8c1YXMR0ftycdB5wGTh83KgQEDFfhyDztDHwT_J4Ey37nhNdGaanX8P6dYuEieKrSB8mFtx2xFftjfwovUDqXwhQwJlDF9AKOIeq2zI-nE5AcwkMj4lY3EtW76CcKRabDSeXufSmRHB5Ol2rQJ5N-dEyy2b2g0F-5x7WlO7kL0_NZMuWRsAFcCdzkpycIJZ3w1-vFe2zOz3KCvZeqStpzoxVNK1j6Qbd90W6p2WyaDS87a2WCtzDKgGmrrvSxzdFeGRt9P9XFOeSP5lHmKzFhIOBHCWWS5Z3Aj2MR0WhgvVIw267KN4zIADJnvpT3ud_RPhH-tQdaF4JmVkGoshkQ";
	private ResourceServerTAI tai;

	@Before
	public void initialize() throws Exception {
		tai = new ResourceServerTAI();
		tai.initialize(createProperties());
	}

	private Properties createProperties() {
		Properties properties = new Properties();
		properties.put(Configuration.ACCEPTED_ISSUER, ISSUER);
		properties.put(Configuration.GROUP_CLAIM, GROUP_ID);
		properties.put(Configuration.REALM, REALM);
		properties.put(Configuration.SIGNATURE_ALGORITHM, Configuration.SA.HS256.toString());
		properties.put(Configuration.SECRET_KEY, TEST_SECRET);
		return properties;
	}

	@Test
	public void testNoAuthorizationHeader() throws Exception {
		HttpServletRequest req = createMock(HttpServletRequest.class);
		expect(req.getHeader("Authorization")).andReturn(null);

		replayAll();
		boolean result = tai.isTargetInterceptor(req);
		verifyAll();

		assertFalse(result);
	}

	@Test
	public void testNoTokenAuthorizationHeader() throws Exception {
		HttpServletRequest req = createMock(HttpServletRequest.class);
		expect(req.getHeader("Authorization")).andReturn("Basic FOO");

		replayAll();
		boolean result = tai.isTargetInterceptor(req);
		verifyAll();

		assertFalse(result);
	}

	@Test
	public void testValidToken() throws Exception {
		HttpServletRequest req = createMock(HttpServletRequest.class);
		HttpServletResponse res = createMock(HttpServletResponse.class);
		String token = createToken(ISSUER, TimeUnit.HOURS.toMillis(2));
		expect(req.getHeader("Authorization")).andReturn("Bearer " + token);

		replayAll();
		Subject subject = tai.authenticate(req, res);
		verifyAll();

		assertNotNull(subject);
		@SuppressWarnings("unchecked")
		Hashtable<String, Object> properties = subject.getPublicCredentials(Hashtable.class).iterator().next();
		assertEquals(properties.get(AttributeNameConstants.WSCREDENTIAL_REALM), REALM);
		assertEquals(properties.get(AttributeNameConstants.WSCREDENTIAL_UNIQUEID), SUBJECT);
		assertEquals(properties.get(AttributeNameConstants.WSCREDENTIAL_SECURITYNAME), SUBJECT);
		assertEquals(properties.get(AttributeNameConstants.WSCREDENTIAL_GROUPS), Arrays.asList(GROUPS));
	}

	@Test(expected = InvalidClaimException.class)
	public void testInvalidIssuerToken() throws Exception {
		HttpServletRequest req = createMock(HttpServletRequest.class);
		HttpServletResponse res = createMock(HttpServletResponse.class);
		String token = createToken(ISSUER + "1", TimeUnit.HOURS.toMillis(2));
		expect(req.getHeader("Authorization")).andReturn("Bearer " + token);

		replayAll();
		tai.authenticate(req, res);
	}

	@Test(expected = TokenExpiredException.class)
	public void testExpiredToken() throws Exception {
		HttpServletRequest req = createMock(HttpServletRequest.class);
		HttpServletResponse res = createMock(HttpServletResponse.class);
		String token = createToken(ISSUER, TimeUnit.HOURS.toMillis(-2));
		expect(req.getHeader("Authorization")).andReturn("Bearer " + token);

		replayAll();
		tai.authenticate(req, res);
	}

	private String createToken(String issuer, long duration) throws Exception {
		Date issuedAt = new Date(System.currentTimeMillis());
		Date expiresAt = new Date(issuedAt.getTime() + duration);
		return JWT.create().withIssuer(issuer).withSubject(SUBJECT).withArrayClaim(GROUP_ID, GROUPS)
				.withIssuedAt(issuedAt).withExpiresAt(expiresAt).sign(Algorithm.HMAC256(TEST_SECRET));
	}
}
