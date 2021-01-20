package havis.net.server.http;

import havis.net.server.http.Authorization.AuthMode;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.Principal;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

import javax.xml.bind.DatatypeConverter;

import org.junit.Assert;
import org.junit.Test;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;

import mockit.Deencapsulation;
import mockit.Mocked;
import mockit.NonStrictExpectations;

public class AuthorizationTest {

	private static void reset(AuthMode authMode) {
		getSessions().clear();
		Map<String, String> names = Deencapsulation.getField(Authorization.class, "names");
		names.clear();
		Deencapsulation.setField(Authorization.class, "authMode", authMode);
		Set<String> permitAll = Deencapsulation.getField(Authorization.class, "permitAll");
		permitAll.clear();
	}

	private static LinkedHashMap<String, Principal> getSessions() {
		return Deencapsulation.getField(Authorization.class, "sessions");
	}

	private void mockAccessToBase(final ProcessBuilder processBuilder, final Process process, final String resultJson) throws Exception {
		new NonStrictExpectations() {
			{
				processBuilder.start();
				result = process;

				process.getInputStream();
				result = new ByteArrayInputStream(resultJson.getBytes());
			}
		};
		// container name
		Deencapsulation.setField(Authorization.class, "hostname", "Apps");
	}

	private static void addSession(String cookie, Principal principal) {
		LinkedHashMap<String, Principal> sessions = Deencapsulation.getField(Authorization.class, "sessions");
		sessions.put(cookie, principal);
	}

	@Test
	public void getPrincipalWithLocalAccessAndWithBrowserAndWithoutCredentialsAndWithoutCookie(@Mocked final HttpExchange exchange) throws Exception {
		reset(AuthMode.MICA);
		final Headers requestHeaders = new Headers();
		requestHeaders.put("User-agent", Arrays.asList("something Gecko something"));
		final Headers responseHeaders = new Headers();
		final URI uri = new URI("http://test");
		final InetSocketAddress loopback = new InetSocketAddress(InetAddress.getLoopbackAddress(), 80);
		new NonStrictExpectations() {
			{
				exchange.getRequestHeaders();
				result = requestHeaders;

				exchange.getResponseHeaders();
				result = responseHeaders;

				exchange.getRequestURI();
				result = uri;

				exchange.getLocalAddress();
				result = loopback;

				exchange.getRemoteAddress();
				result = loopback;
			}
		};
		Principal principal = Authorization.getPrincipal(exchange);
		Assert.assertNull(principal);

		Assert.assertEquals(1, responseHeaders.size());
		List<String> value = responseHeaders.get("WWW-Authenticate");
		Assert.assertNotNull(value);
		Assert.assertEquals(1, value.size());
		Assert.assertEquals("Basic realm=\"HARTING\"", value.get(0));

		LinkedHashMap<String, Principal> sessions = getSessions();
		Assert.assertEquals(0, sessions.size());
	}

	@Test
	public void getPrincipalWithLocalAccessAndWithBrowserAndWithCredentialsAndWithoutCookie(@Mocked final HttpExchange exchange) throws Exception {
		reset(AuthMode.MICA);
		final Headers requestHeaders = new Headers();
		requestHeaders.put("User-agent", Arrays.asList("something Gecko something"));
		requestHeaders.put("Authorization", Arrays.asList("Basic " + DatatypeConverter.printBase64Binary("admin:admin".getBytes())));
		final Headers responseHeaders = new Headers();
		final URI uri = new URI("http://test");
		final InetSocketAddress loopback = new InetSocketAddress(InetAddress.getLoopbackAddress(), 80);
		new NonStrictExpectations() {
			{
				exchange.getRequestHeaders();
				result = requestHeaders;

				exchange.getResponseHeaders();
				result = responseHeaders;

				exchange.getRequestURI();
				result = uri;

				exchange.getLocalAddress();
				result = loopback;

				exchange.getRemoteAddress();
				result = loopback;
			}
		};
		Principal principal = Authorization.getPrincipal(exchange);
		Assert.assertNotNull(principal);
		Assert.assertEquals("admin", principal.getName());

		Assert.assertEquals(0, responseHeaders.size());

		LinkedHashMap<String, Principal> sessions = getSessions();
		Assert.assertEquals(0, sessions.size());
	}

	@Test
	public void getPrincipalWithBasicAndWithoutCredentialsAndWithoutCookie(@Mocked final HttpExchange exchange) throws Exception {
		reset(AuthMode.BASIC_NOVERIFY);
		final Headers requestHeaders = new Headers();
		final Headers responseHeaders = new Headers();
		final URI uri = new URI("http://test");
		final InetSocketAddress localAddress = new InetSocketAddress("10.10.10.10", 80);
		final InetSocketAddress remoteAddress = new InetSocketAddress("10.10.10.10", 80);
		new NonStrictExpectations() {
			{
				exchange.getRequestHeaders();
				result = requestHeaders;

				exchange.getResponseHeaders();
				result = responseHeaders;

				exchange.getRequestURI();
				result = uri;

				exchange.getLocalAddress();
				result = localAddress;

				exchange.getRemoteAddress();
				result = remoteAddress;
			}
		};
		Principal principal = Authorization.getPrincipal(exchange);
		Assert.assertNull(principal);

		Assert.assertEquals(1, responseHeaders.size());
		List<String> value = responseHeaders.get("WWW-Authenticate");
		Assert.assertNotNull(value);
		Assert.assertEquals(1, value.size());
		Assert.assertEquals("Basic realm=\"HARTING\"", value.get(0));

		LinkedHashMap<String, Principal> sessions = getSessions();
		Assert.assertEquals(0, sessions.size());
	}

	@Test
	public void getPrincipalWithBasicAndWithCredentialsAndWithoutCookie(@Mocked final HttpExchange exchange) throws Exception {
		reset(AuthMode.BASIC_NOVERIFY);
		final Headers requestHeaders = new Headers();
		requestHeaders.put("Authorization", Arrays.asList("Basic " + DatatypeConverter.printBase64Binary("admin:admin".getBytes())));
		final Headers responseHeaders = new Headers();
		final URI uri = new URI("http://test");
		final InetSocketAddress localAddress = new InetSocketAddress("10.10.10.10", 80);
		final InetSocketAddress remoteAddress = new InetSocketAddress("10.10.10.10", 80);
		new NonStrictExpectations() {
			{
				exchange.getRequestHeaders();
				result = requestHeaders;

				exchange.getResponseHeaders();
				result = responseHeaders;

				exchange.getRequestURI();
				result = uri;

				exchange.getLocalAddress();
				result = localAddress;

				exchange.getRemoteAddress();
				result = remoteAddress;
			}
		};
		Principal principal = Authorization.getPrincipal(exchange);
		Assert.assertNotNull(principal);
		Assert.assertEquals("admin", principal.getName());

		Assert.assertEquals(0, responseHeaders.size());

		LinkedHashMap<String, Principal> sessions = getSessions();
		Assert.assertEquals(0, sessions.size());
	}

	@Test
	public void getPrincipalWithLocalAccessAndWithCredentialsAndWithoutCookie(@Mocked final HttpExchange exchange) throws Exception {
		reset(AuthMode.MICA);
		final Headers requestHeaders = new Headers();
		// username only from postinst scripts
		requestHeaders.put("Authorization", Arrays.asList("Basic " + DatatypeConverter.printBase64Binary("admin:".getBytes())));
		final Headers responseHeaders = new Headers();
		final URI uri = new URI("http://test");
		final InetSocketAddress loopback = new InetSocketAddress(InetAddress.getLoopbackAddress(), 80);
		new NonStrictExpectations() {
			{
				exchange.getRequestHeaders();
				result = requestHeaders;

				exchange.getResponseHeaders();
				result = responseHeaders;

				exchange.getRequestURI();
				result = uri;

				exchange.getLocalAddress();
				result = loopback;

				exchange.getRemoteAddress();
				result = loopback;
			}
		};
		Principal principal = Authorization.getPrincipal(exchange);
		Assert.assertNotNull(principal);
		Assert.assertEquals("admin", principal.getName());

		Assert.assertEquals(0, responseHeaders.size());

		LinkedHashMap<String, Principal> sessions = getSessions();
		Assert.assertEquals(0, sessions.size());
	}

	@Test
	public void getPrincipalWithRemoteAccessAndWithTokenInRefererUriAndWithoutAndWithCookie(@Mocked final HttpExchange exchange, @Mocked final ProcessBuilder processBuilder, @Mocked final Process process) throws Exception {
		mockAccessToBase(processBuilder, process, "{\"result\": \"0vLhB9GmNb\", \"id\": 1, \"jsonrpc\": \"2.0\"}\n{\"result\": {\"role\": \"admin\", \"host\": \"::ffff:10.10.10.10\"}, \"id\": 2, \"jsonrpc\": \"2.0\"}");
		reset(AuthMode.MICA);
		final Headers requestHeaders = new Headers();
		requestHeaders.put("Referer", Arrays.asList("http://test?token=mytoken"));
		final Headers responseHeaders = new Headers();
		final URI uri = new URI("http://test");
		final InetSocketAddress localAddress = new InetSocketAddress("10.10.10.10", 80);
		final InetSocketAddress remoteAddress = new InetSocketAddress("10.10.10.10", 80);
		new NonStrictExpectations() {
			{
				exchange.getRequestHeaders();
				result = requestHeaders;

				exchange.getResponseHeaders();
				result = responseHeaders;

				exchange.getRequestURI();
				result = uri;

				exchange.getLocalAddress();
				result = localAddress;

				exchange.getRemoteAddress();
				result = remoteAddress;
			}
		};
		Principal principal = Authorization.getPrincipal(exchange);
		Assert.assertNotNull(principal);
		Assert.assertEquals("admin", principal.getName());

		Assert.assertEquals(1, responseHeaders.size());
		List<String> value = responseHeaders.get("Set-Cookie");
		Assert.assertNotNull(value);
		Assert.assertEquals(1, value.size());
		String cookie = value.get(0);
		Assert.assertTrue(Pattern.matches("JSESSIONID=[0-9a-z-]+;Max-Age=86400;Path=/Apps;SameSite=Lax", cookie));
		String sessionId = cookie.substring(0, cookie.indexOf(";"));

		LinkedHashMap<String, Principal> sessions = getSessions();
		Assert.assertEquals(1, sessions.size());
		Assert.assertNotNull(sessions.get(sessionId));
		Assert.assertEquals("admin", sessions.get(sessionId).getName());

		// second request without cookie
		requestHeaders.clear();
		requestHeaders.put("Referer", Arrays.asList("http://test?token=mytoken"));
		responseHeaders.clear();

		principal = Authorization.getPrincipal(exchange);
		Assert.assertNotNull(principal);
		Assert.assertEquals("admin", principal.getName());

		Assert.assertEquals(1, responseHeaders.size());
		value = responseHeaders.get("Set-Cookie");
		Assert.assertNotNull(value);
		Assert.assertEquals(1, value.size());
		cookie = value.get(0);
		Assert.assertTrue(Pattern.matches("JSESSIONID=[0-9a-z-]+;Max-Age=86400;Path=/Apps;SameSite=Lax", cookie));
		sessionId = cookie.substring(0, cookie.indexOf(";"));

		sessions = getSessions();
		Assert.assertEquals(2, sessions.size());
		Assert.assertNotNull(sessions.get(sessionId));
		Assert.assertEquals("admin", sessions.get(sessionId).getName());

		// third request with cookie
		requestHeaders.clear();
		requestHeaders.put("Referer", Arrays.asList("http://test?token=mytoken"));
		requestHeaders.put("Cookie", Arrays.asList(sessionId));
		responseHeaders.clear();

		principal = Authorization.getPrincipal(exchange);
		Assert.assertNotNull(principal);
		Assert.assertEquals("admin", principal.getName());

		Assert.assertEquals(1, responseHeaders.size());
		value = responseHeaders.get("Set-Cookie");
		Assert.assertNotNull(value);
		Assert.assertEquals(1, value.size());
		cookie = value.get(0);
		Assert.assertTrue(Pattern.matches(sessionId + ";Max-Age=86400;Path=/Apps;SameSite=Lax", cookie));

		sessions = getSessions();
		Assert.assertEquals(2, sessions.size());
		Assert.assertNotNull(sessions.get(sessionId));
		Assert.assertEquals("admin", sessions.get(sessionId).getName());
	}

	@Test
	public void getPrincipalWithRemoteAccessAndWithTokenInRequestUriWithoutAndWithCookie(@Mocked final HttpExchange exchange, @Mocked final ProcessBuilder processBuilder, @Mocked final Process process) throws Exception {
		mockAccessToBase(processBuilder, process, "{\"result\": \"0vLhB9GmNb\", \"id\": 1, \"jsonrpc\": \"2.0\"}\n{\"result\": {\"role\": \"admin\", \"host\": \"::ffff:10.10.10.10\"}, \"id\": 2, \"jsonrpc\": \"2.0\"}");
		reset(AuthMode.MICA);
		final Headers requestHeaders = new Headers();
		final Headers responseHeaders = new Headers();
		final URI uri = new URI("http://test?token=mytoken");
		final InetSocketAddress localAddress = new InetSocketAddress("10.10.10.10", 80);
		final InetSocketAddress remoteAddress = new InetSocketAddress("10.10.10.10", 80);
		new NonStrictExpectations() {
			{
				exchange.getRequestHeaders();
				result = requestHeaders;

				exchange.getResponseHeaders();
				result = responseHeaders;

				exchange.getRequestURI();
				result = uri;

				exchange.getLocalAddress();
				result = localAddress;

				exchange.getRemoteAddress();
				result = remoteAddress;
			}
		};
		Principal principal = Authorization.getPrincipal(exchange);
		Assert.assertNotNull(principal);
		Assert.assertEquals("admin", principal.getName());

		Assert.assertEquals(1, responseHeaders.size());
		List<String> value = responseHeaders.get("Set-Cookie");
		Assert.assertNotNull(value);
		Assert.assertEquals(1, value.size());
		String cookie = value.get(0);
		Assert.assertTrue(Pattern.matches("JSESSIONID=[0-9a-z-]+;Max-Age=86400;Path=/Apps;SameSite=Lax", cookie));
		String sessionId = cookie.substring(0, cookie.indexOf(";"));

		LinkedHashMap<String, Principal> sessions = getSessions();
		Assert.assertEquals(1, sessions.size());
		Assert.assertNotNull(sessions.get(sessionId));
		Assert.assertEquals("admin", sessions.get(sessionId).getName());

		// second request without cookie
		requestHeaders.clear();
		responseHeaders.clear();

		principal = Authorization.getPrincipal(exchange);
		Assert.assertNotNull(principal);
		Assert.assertEquals("admin", principal.getName());

		Assert.assertEquals(1, responseHeaders.size());
		value = responseHeaders.get("Set-Cookie");
		Assert.assertNotNull(value);
		Assert.assertEquals(1, value.size());
		cookie = value.get(0);
		Assert.assertTrue(Pattern.matches("JSESSIONID=[0-9a-z-]+;Max-Age=86400;Path=/Apps;SameSite=Lax", cookie));
		sessionId = cookie.substring(0, cookie.indexOf(";"));

		sessions = getSessions();
		Assert.assertEquals(2, sessions.size());
		Assert.assertNotNull(sessions.get(sessionId));
		Assert.assertEquals("admin", sessions.get(sessionId).getName());

		// third request with cookie
		requestHeaders.clear();
		requestHeaders.put("Cookie", Arrays.asList(sessionId));
		responseHeaders.clear();

		principal = Authorization.getPrincipal(exchange);
		Assert.assertNotNull(principal);
		Assert.assertEquals("admin", principal.getName());

		Assert.assertEquals(1, responseHeaders.size());
		value = responseHeaders.get("Set-Cookie");
		Assert.assertNotNull(value);
		Assert.assertEquals(1, value.size());
		cookie = value.get(0);
		Assert.assertTrue(Pattern.matches(sessionId + ";Max-Age=86400;Path=/Apps;SameSite=Lax", cookie));

		sessions = getSessions();
		Assert.assertEquals(2, sessions.size());
		Assert.assertNotNull(sessions.get(sessionId));
		Assert.assertEquals("admin", sessions.get(sessionId).getName());
	}

	@Test
	public void getPrincipalWithRemoteAccessAndWithCredentialsAndWithoutCookie(@Mocked final HttpExchange exchange, @Mocked final ProcessBuilder processBuilder, @Mocked final Process process) throws Exception {
		mockAccessToBase(processBuilder, process, "{\"result\": \"mytoken\", \"id\": 1, \"jsonrpc\": \"2.0\"}");
		reset(AuthMode.MICA);
		final Headers requestHeaders = new Headers();
		requestHeaders.put("Authorization", Arrays.asList("Basic " + DatatypeConverter.printBase64Binary("admin:admin".getBytes())));
		final Headers responseHeaders = new Headers();
		final URI uri = new URI("http://test");
		final InetSocketAddress localAddress = new InetSocketAddress("10.10.10.10", 80);
		final InetSocketAddress remoteAddress = new InetSocketAddress("10.10.10.10", 80);
		new NonStrictExpectations() {
			{
				exchange.getRequestHeaders();
				result = requestHeaders;

				exchange.getResponseHeaders();
				result = responseHeaders;

				exchange.getRequestURI();
				result = uri;

				exchange.getLocalAddress();
				result = localAddress;

				exchange.getRemoteAddress();
				result = remoteAddress;
			}
		};
		Principal principal = Authorization.getPrincipal(exchange);
		Assert.assertNotNull(principal);
		Assert.assertEquals("admin", principal.getName());

		Assert.assertEquals(1, responseHeaders.size());
		List<String> value = responseHeaders.get("Set-Cookie");
		Assert.assertNotNull(value);
		Assert.assertEquals(1, value.size());
		String cookie = value.get(0);
		Assert.assertTrue(Pattern.matches("JSESSIONID=[0-9a-z-]+;Max-Age=86400;Path=/Apps;SameSite=Lax", cookie));
		String sessionId = cookie.substring(0, cookie.indexOf(";"));

		LinkedHashMap<String, Principal> sessions = getSessions();
		Assert.assertEquals(1, sessions.size());
		Assert.assertNotNull(sessions.get(sessionId));
		Assert.assertEquals("admin", sessions.get(sessionId).getName());
	}

	@Test
	public void getPrincipalWithoutAnyAuthWithCookie(@Mocked final HttpExchange exchange) throws Exception {
		reset(AuthMode.MICA);
		Principal principal = new Principal() {
			@Override
			public String getName() {
				return "admin";
			}
		};
		addSession("JSESSIONID=mycookie", principal);
		final Headers requestHeaders = new Headers();
		requestHeaders.put("User-agent", Arrays.asList("something Gecko something"));
		requestHeaders.put("Cookie", Arrays.asList("JSESSIONID=mycookie"));
		final Headers responseHeaders = new Headers();
		final URI uri = new URI("http://test");
		final InetSocketAddress localAddress = new InetSocketAddress("10.10.10.10", 80);
		final InetSocketAddress remoteAddress = new InetSocketAddress("10.10.10.10", 80);
		new NonStrictExpectations() {
			{
				exchange.getRequestHeaders();
				result = requestHeaders;

				exchange.getResponseHeaders();
				result = responseHeaders;

				exchange.getRequestURI();
				result = uri;

				exchange.getLocalAddress();
				result = localAddress;

				exchange.getRemoteAddress();
				result = remoteAddress;
			}
		};
		Principal result = Authorization.getPrincipal(exchange);
		Assert.assertSame(principal, result);

		Assert.assertEquals(1, responseHeaders.size());
		List<String> value = responseHeaders.get("Set-Cookie");
		Assert.assertNotNull(value);
		Assert.assertEquals(1, value.size());
		String cookie = value.get(0);
		Assert.assertTrue(Pattern.matches("JSESSIONID=[0-9a-z-]+;Max-Age=86400;Path=/Apps;SameSite=Lax", cookie));
		String sessionId = cookie.substring(0, cookie.indexOf(";"));

		LinkedHashMap<String, Principal> sessions = getSessions();
		Assert.assertEquals(1, sessions.size());
		Assert.assertNotNull(sessions.get(sessionId));
		Assert.assertEquals("admin", sessions.get(sessionId).getName());
	}
	
	@Test
	public void getPrincipalWithoutAnyAuthWithMultipleCookies(@Mocked final HttpExchange exchange) throws Exception {
		reset(AuthMode.MICA);
		Principal principal = new Principal() {
			@Override
			public String getName() {
				return "admin";
			}
		};
		addSession("JSESSIONID=mycookie", principal);
		final Headers requestHeaders = new Headers();
		requestHeaders.put("User-agent", Arrays.asList("something Gecko something"));
		requestHeaders.put("Cookie", Arrays.asList("JSESSIONID=mycookie; something=else"));
		final Headers responseHeaders = new Headers();
		final URI uri = new URI("http://test");
		final InetSocketAddress localAddress = new InetSocketAddress("10.10.10.10", 80);
		final InetSocketAddress remoteAddress = new InetSocketAddress("10.10.10.10", 80);
		new NonStrictExpectations() {
			{
				exchange.getRequestHeaders();
				result = requestHeaders;

				exchange.getResponseHeaders();
				result = responseHeaders;

				exchange.getRequestURI();
				result = uri;

				exchange.getLocalAddress();
				result = localAddress;

				exchange.getRemoteAddress();
				result = remoteAddress;
			}
		};
		Principal result = Authorization.getPrincipal(exchange);
		Assert.assertSame(principal, result);

		Assert.assertEquals(1, responseHeaders.size());
		List<String> value = responseHeaders.get("Set-Cookie");
		Assert.assertNotNull(value);
		Assert.assertEquals(1, value.size());
		String cookie = value.get(0);
		Assert.assertTrue(Pattern.matches("JSESSIONID=[0-9a-z-]+;Max-Age=86400;Path=/Apps;SameSite=Lax", cookie));
		String sessionId = cookie.substring(0, cookie.indexOf(";"));

		LinkedHashMap<String, Principal> sessions = getSessions();
		Assert.assertEquals(1, sessions.size());
		Assert.assertNotNull(sessions.get(sessionId));
		Assert.assertEquals("admin", sessions.get(sessionId).getName());
	}

	@Test
	public void getPrincipalWithoutAnyAuthWithAnonymous(@Mocked final HttpExchange exchange) throws Exception {
		anonymous(exchange, new String[] { "/somepath" }, "http://test/somepath", "anonymous");
		anonymous(exchange, new String[] { "/somepath" }, "http://test/somepath/something", "anonymous");
		anonymous(exchange, new String[] { "/somepath" }, "http://test/somepathsomething", "anonymous");
		anonymous(exchange, new String[] { "/somepath", "/other" }, "http://test/other", "anonymous");
		anonymous(exchange, new String[] { "/somepath" }, "http://test/other", null);
	}

	@Test
	public void getPrincipalWithNoneAuth(@Mocked final HttpExchange exchange) throws Exception {
		none(exchange, "http://test/somepath", "admin");
		none(exchange, "http://test/somepath/something", "admin");
	}

	private void none(final HttpExchange exchange, String uri, String expectedPrincipal) throws URISyntaxException, IOException {
		reset(AuthMode.NONE);
		final Headers requestHeaders = new Headers();
		requestHeaders.put("User-agent", Arrays.asList("something Gecko something"));
		final Headers responseHeaders = new Headers();
		final URI u = new URI(uri);
		final InetSocketAddress localAddress = new InetSocketAddress("10.10.10.10", 80);
		final InetSocketAddress remoteAddress = new InetSocketAddress("10.10.10.10", 80);
		new NonStrictExpectations() {
			{
				exchange.getRequestHeaders();
				result = requestHeaders;

				exchange.getResponseHeaders();
				result = responseHeaders;

				exchange.getRequestURI();
				result = u;

				exchange.getLocalAddress();
				result = localAddress;

				exchange.getRemoteAddress();
				result = remoteAddress;
			}
		};
		Principal principal = Authorization.getPrincipal(exchange);
		Assert.assertNotNull(principal);
		Assert.assertEquals(expectedPrincipal, principal.getName());
		Assert.assertEquals(0, responseHeaders.size());

		LinkedHashMap<String, Principal> sessions = getSessions();
		Assert.assertEquals(0, sessions.size());
	}

	private void anonymous(final HttpExchange exchange, String[] permitAll, String uri, String expectedPrincipal) throws URISyntaxException, IOException {
		reset(AuthMode.MICA);
		Authorization.addPermitAll(permitAll);
		final Headers requestHeaders = new Headers();
		requestHeaders.put("User-agent", Arrays.asList("something Gecko something"));
		final Headers responseHeaders = new Headers();
		final URI u = new URI(uri);
		final InetSocketAddress localAddress = new InetSocketAddress("10.10.10.10", 80);
		final InetSocketAddress remoteAddress = new InetSocketAddress("10.10.10.10", 80);
		new NonStrictExpectations() {
			{
				exchange.getRequestHeaders();
				result = requestHeaders;

				exchange.getResponseHeaders();
				result = responseHeaders;

				exchange.getRequestURI();
				result = u;

				exchange.getLocalAddress();
				result = localAddress;

				exchange.getRemoteAddress();
				result = remoteAddress;
			}
		};
		Principal principal = Authorization.getPrincipal(exchange);
		if (expectedPrincipal == null) {
			// not permitted anonymously
			Assert.assertNull(principal);

			Assert.assertEquals(1, responseHeaders.size());

			List<String> value = responseHeaders.get("WWW-Authenticate");
			Assert.assertNotNull(value);
			Assert.assertEquals(1, value.size());
			Assert.assertEquals("Basic realm=\"HARTING\"", value.get(0));
		} else {
			Assert.assertNotNull(principal);
			Assert.assertEquals(expectedPrincipal, principal.getName());

			Assert.assertEquals(0, responseHeaders.size());
		}

		LinkedHashMap<String, Principal> sessions = getSessions();
		Assert.assertEquals(0, sessions.size());
	}

	@Test
	public void getPrincipalWithBasicAndWithCredentialsAndWithVerificationAndWithoutCookie(@Mocked final HttpExchange exchange, @Mocked final ProcessBuilder processBuilder,
			@Mocked final Process process) throws Exception {
		verify(exchange, processBuilder, process, "admin:p4ssw0rd", "admin", "p4ssw0rd", true);
		verify(exchange, processBuilder, process, "admin:p4ssw0rd", "admin", "p4ssw0rd", false);
		verify(exchange, processBuilder, process, "admin", "admin", "", false);
	}

	private void verify(final HttpExchange exchange, final ProcessBuilder processBuilder, final Process process, final String credentials,
			final String username, final String password, final boolean verified) throws URISyntaxException, IOException, InterruptedException {
		reset(AuthMode.BASIC);
		final Headers requestHeaders = new Headers();
		requestHeaders.put("Authorization", Arrays.asList("Basic " + DatatypeConverter.printBase64Binary(credentials.getBytes())));
		final Headers responseHeaders = new Headers();
		final URI uri = new URI("http://test");
		final InetSocketAddress localAddress = new InetSocketAddress("10.10.10.10", 80);
		final InetSocketAddress remoteAddress = new InetSocketAddress("10.10.10.10", 80);
		final ByteArrayOutputStream processStdin = new ByteArrayOutputStream();
		new NonStrictExpectations() {
			{
				exchange.getRequestHeaders();
				result = requestHeaders;

				exchange.getResponseHeaders();
				result = responseHeaders;

				exchange.getRequestURI();
				result = uri;

				exchange.getLocalAddress();
				result = localAddress;

				exchange.getRemoteAddress();
				result = remoteAddress;

				processBuilder.start();
				result = process;

				process.getOutputStream();
				result = processStdin;

				process.waitFor();
				result = Long.valueOf(verified ? 0 : 1);
			}
		};
		Principal principal = Authorization.getPrincipal(exchange);

		Assert.assertEquals(password, processStdin.toString());

		if (verified) {
			Assert.assertNotNull(principal);
			Assert.assertEquals(username, principal.getName());

			Assert.assertEquals(1, responseHeaders.size());
			List<String> value = responseHeaders.get("Set-Cookie");
			Assert.assertNotNull(value);
			Assert.assertEquals(1, value.size());
			String cookie = value.get(0);
			Assert.assertTrue(Pattern.matches("JSESSIONID=[0-9a-z-]+;Max-Age=86400;Path=/Apps;SameSite=Lax", cookie));
			String sessionId = cookie.substring(0, cookie.indexOf(";"));

			LinkedHashMap<String, Principal> sessions = getSessions();
			Assert.assertEquals(1, sessions.size());
			Assert.assertNotNull(sessions.get(sessionId));
			Assert.assertEquals(username, sessions.get(sessionId).getName());
		} else {
			Assert.assertNull(principal);

			List<String> value = responseHeaders.get("WWW-Authenticate");
			Assert.assertNotNull(value);
			Assert.assertEquals(1, value.size());
			Assert.assertEquals("Basic realm=\"HARTING\"", value.get(0));

			LinkedHashMap<String, Principal> sessions = getSessions();
			Assert.assertEquals(0, sessions.size());
		}
	}

	//@Test
	public void getPrinicpalWithUserVerificationAndWithoutCookie(@Mocked final HttpExchange exchange) throws URISyntaxException, IOException, InterruptedException {
		reset(AuthMode.BASIC);
		final Headers requestHeaders = new Headers();
		requestHeaders.put("Authorization", Arrays.asList("Basic " + DatatypeConverter.printBase64Binary("ftpuser:ftpuser".getBytes())));
		final Headers responseHeaders = new Headers();
		final URI uri = new URI("http://test");
		final InetSocketAddress localAddress = new InetSocketAddress("10.10.10.10", 80);
		final InetSocketAddress remoteAddress = new InetSocketAddress("10.10.10.10", 80);
		new NonStrictExpectations() {
			{
				exchange.getRequestHeaders();
				result = requestHeaders;

				exchange.getResponseHeaders();
				result = responseHeaders;

				exchange.getRequestURI();
				result = uri;

				exchange.getLocalAddress();
				result = localAddress;

				exchange.getRemoteAddress();
				result = remoteAddress;
			}
		};
		Principal principal = Authorization.getPrincipal(exchange);
		Assert.assertNotNull(principal);
		Assert.assertEquals("ftpuser", principal.getName());

		Assert.assertEquals(1, responseHeaders.size());
		List<String> value = responseHeaders.get("Set-Cookie");
		Assert.assertNotNull(value);
		Assert.assertEquals(1, value.size());
		String cookie = value.get(0);
		Assert.assertTrue(Pattern.matches("JSESSIONID=[0-9a-z-]+;Max-Age=86400;Path=/Apps;SameSite=Lax", cookie));
		String sessionId = cookie.substring(0, cookie.indexOf(";"));

		LinkedHashMap<String, Principal> sessions = getSessions();
		Assert.assertEquals(1, sessions.size());
		Assert.assertNotNull(sessions.get(sessionId));
		Assert.assertEquals("ftpuser", sessions.get(sessionId).getName());
	}
}
