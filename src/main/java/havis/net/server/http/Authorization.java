package havis.net.server.http;

import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.Reader;
import java.io.UnsupportedEncodingException;
import java.io.Writer;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.Principal;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArraySet;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.xml.bind.DatatypeConverter;

import com.sun.net.httpserver.HttpExchange;

public class Authorization {

	public final static String BASIC = "havis.net.server.http.basic";
	public final static String AUTH_MODE = "havis.net.server.http.auth";
	private final static String VERIFY_BASIC_CREDENTIALS_COMMAND = "pam-check-user";
	private final static String URL = "https://mica/ws/";

	private static final String VALIDATE_TOKEN_GROUP = "role";
	private static final Pattern VALIDATE_TOKEN_PATTERN = Pattern.compile("^\\{.*\"result\":\\s*\\{.*\"role\":\\s*\"(?<" + VALIDATE_TOKEN_GROUP + ">[^\\\"]*)\".*\\}.*\\}$");

	private static final String GET_TOKEN_GROUP = "result";
	private static final Pattern GET_TOKEN_PATTERN = Pattern.compile("^\\{.*\"result\":\\s*\"(?<" + GET_TOKEN_GROUP + ">[^\\\"]*)\".*\\}$");

	private final static Logger log = Logger.getLogger(Authorization.class.getName());

	private static AuthMode authMode;
	private static String hostname;

	private final static String COOKIE_KEY = "JSESSIONID";
	private static LinkedHashMap<String, Principal> sessions = new LinkedHashMap<>();
	private static Map<String, String> names = new HashMap<>();

	private final static Set<String> permitAll = new CopyOnWriteArraySet<>();

	static enum AuthMode {
		NONE(false, "no authentification"), BASIC_NOVERIFY(true, "use basic authentication without verification"),
		BASIC(true, "use basic authentication with verification against linux user database"), MICA(false, "use MICA base authentication");

		private String description;
		private boolean isBasic;

		private AuthMode(boolean isBasic, String descripton) {
			this.isBasic = isBasic;
			this.description = descripton;
		}

		public boolean isBasic() {
			return this.isBasic;
		}

		public String getDescription() {
			return this.description;
		}
	}

	/**
	 * Initializes the SSL context. Overrides the default trust manager and host
	 * name verifier.
	 */
	static {
		String basic = System.getProperty(BASIC, "").trim();
		String auth = System.getProperty(AUTH_MODE, "").trim();
		if (auth.length() > 0 && basic.length() > 0) {
			log.log(Level.SEVERE, "Property " + BASIC + " will be ignored, since " + AUTH_MODE + " is set.");
		}
		if (auth.length() == 0 && basic.length() > 0) {
			Boolean b = Boolean.valueOf(basic);
			if (Boolean.TRUE.equals(b))
				Authorization.authMode = AuthMode.BASIC;
			else if (Boolean.FALSE.equals(b))
				Authorization.authMode = AuthMode.BASIC_NOVERIFY;
			else
				Authorization.authMode = AuthMode.MICA;
		} else if (auth.length() > 0) {
			for (AuthMode m : AuthMode.values()) {
				if (auth.equalsIgnoreCase(m.name())) {
					Authorization.authMode = m;
					break;
				}
			}
		}

		if (Authorization.authMode == null) {
			// fall back to MICA by default
			Authorization.authMode = AuthMode.MICA;
		}
		log.log(Level.FINE, "Setting security context of http server to {0}.", Authorization.authMode.getDescription());

		String systemHostname = System.getenv("HOSTNAME");
		hostname = systemHostname != null ? systemHostname : "";
		int index = hostname.indexOf('-');
		hostname = index > 0 ? hostname.substring(0, index) : "";
	}

	static void addPermitAll(String[] list) {
		permitAll.addAll(Arrays.asList(list));
	}

	/**
	 * Gets the principal depending on token string of query parameter.
	 * 
	 * @param token
	 *            The token string
	 * @return The principal, if token is valid, null otherwise.
	 * @throws IOException
	 */
	private static Principal getPrincipal(String token) throws IOException {
		final String name = getName(token);
		if (name != null) {
			return new Principal() {
				@Override
				public String getName() {
					return name;
				}
			};
		}
		return null;
	}

	/**
	 * Gets the token from query
	 * 
	 * @param query
	 *            The query string
	 * @return The token
	 */
	private static String getToken(String query) {
		if (query != null) {
			String[] pairs = query.split("&");
			for (String pair : pairs) {
				String[] parameter = pair.split("=", 2);
				switch (parameter[0]) {
				case "token":
					return parameter[1];
				}
			}
		}
		return null;
	}

	/**
	 * Gets the name by token from WS service of the host.
	 * 
	 * @param token
	 *            The token string
	 * @return The name of the user which owned the token
	 * @throws IOException
	 *             If remote request failed
	 */
	private static String getName(String token) throws IOException {
		String name = names.get(token);
		if (name == null) {
			name = getRoleOfTokenFromBase(token);
			if (name != null) {
				names.put(token, name);
			}
		}
		return name;
	}

	private static String getToken(String user, String password) throws IOException {
		String token = getTokenFromBase(user, password);
		if (token != null) {
			names.put(token, user);
		}
		return token;
	}

	private static String getTokenFromBase(String user, String password) throws IOException {
		StringBuilder command = new StringBuilder();
		command.append("{\"jsonrpc\": \"2.0\", \"id\": 1, \"method\": \"sign_in\", \"params\":{ \"user\": \"" + user + "\", \"pwd\": \"" + password + "\" }}\n");
		String result = null;
		try {
			result = exec(command.toString(), "mica-rpc", URL);
		} catch (IOException | InterruptedException e) {
			log.log(Level.FINE, "Failed to get token", e);
			return null;
		}
		if (result == null) {
			log.log(Level.FINE, "Failed to get token, mica-rpc returned no output");
			return null;
		}
		String[] lines = result.split("\\n");
		for (String line : lines) {
			Matcher m;
			if ((m = GET_TOKEN_PATTERN.matcher(line)).matches()) {
				String data = m.group(GET_TOKEN_GROUP);
				if (data != null)
					return data;
			}
		}
		return null;
	}

	private static String getRoleOfTokenFromBase(String token) throws IOException {
		StringBuilder command = new StringBuilder();
		command.append("{\"jsonrpc\": \"2.0\", \"id\": 1, \"method\": \"validate\", \"params\":{ \"token\": \"" + token + "\" }}");
		String result = null;
		try {
			result = exec(command.toString(), "mica-rpc", URL);
		} catch (IOException | InterruptedException e) {
			log.log(Level.FINE, "Failed to validate token", e);
			return null;
		}
		if (result == null) {
			log.log(Level.FINE, "Failed to validate token, mica-rpc returned no output");
			return null;
		}
		String[] lines = result.split("\\n");
		for (String line : lines) {
			Matcher m;
			if ((m = VALIDATE_TOKEN_PATTERN.matcher(line)).matches()) {
				String data = m.group(VALIDATE_TOKEN_GROUP);
				if (data != null)
					return data;
			}
		}
		log.log(Level.FINE, "Failed to validate token, mica-rpc did not report the expected result: " + result.replace("\n", "; "));
		return null;
	}

	private static void read(InputStream input, StringBuilder builder) throws UnsupportedEncodingException, IOException {
		int size = input.available();
		if (size > 0) {
			char[] b = new char[size];
			try (Reader reader = new InputStreamReader(input)) {
				while ((size = reader.read(b)) > -1) {
					builder.append(b);
				}
			}
		}
	}

	private static String exec(String input, String... command) throws IOException, InterruptedException {
		Process process = new ProcessBuilder(command).start();
		if (input != null) {
			try (BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(process.getOutputStream()))) {
				writer.write(input);
				writer.flush();
			}
		}
		int code = process.waitFor();
		final StringBuilder builder = new StringBuilder();
		read(process.getInputStream(), builder);
		if (code != 0) {
			builder.append("Execution failed\n");
			read(process.getErrorStream(), builder);
			String errorMessage = builder.toString().trim().replace("\n", "; ");
			log.log(Level.FINE, "Execution failed with code {0}: {1}", new Object[] { code, errorMessage });
			throw new IOException(errorMessage);
		}
		return builder.toString();
	}

	/**
	 * Checks if request is locally
	 * 
	 * @param exchange
	 *            The exchange
	 * @return True, if request is locally, false otherwise
	 */
	private static boolean isLocal(HttpExchange exchange) {
		return exchange.getLocalAddress().getAddress().isLoopbackAddress() && exchange.getRemoteAddress().getAddress().isLoopbackAddress();
	}

	/**
	 * Decodes and splits a base64 string
	 * 
	 * @param s
	 *            the Base64 string
	 * @return The decoded string array
	 */
	private static String[] decode(String s) {
		return new String(DatatypeConverter.parseBase64Binary(s), StandardCharsets.UTF_8).split(":", 2);
	}

	/**
	 * Encodes a string to Base64
	 * 
	 * @param s
	 *            The plain string
	 * @return The encoded Base64 String
	 */
	private static String encode(String s) {
		return DatatypeConverter.printBase64Binary(s.getBytes());
	}

	/**
	 * Returns the user credentials form authorization header
	 * 
	 * @param exchange
	 *            The HTTP exchange
	 * @return The credentials
	 */
	private static String[] getCredentials(HttpExchange exchange) {
		final String authorization = exchange.getRequestHeaders().getFirst("Authorization");
		if (authorization != null && authorization.startsWith("Basic "))
			return decode(authorization.substring(6));
		return null;
	}

	/**
	 * Gets the principal depends on AUTH method. If the request is locally the
	 * client gets full access. Otherwise the token will be extracted from
	 * referrer or requested URI. The user will be determined by a remote
	 * request on the host system. The client got a session id with a reference
	 * to the principal.
	 * 
	 * @param exchange
	 *            The exchange
	 * @return The principal
	 * @throws IOException
	 *             If connection failed
	 */
	static Principal getPrincipal(HttpExchange exchange) throws IOException {
		if (authMode == AuthMode.NONE) {
			return new Principal() {
				@Override
				public String getName() {
					return "admin";
				}
			};
		}

		Principal principal = null;
		String path = exchange.getRequestURI().getPath();
		for (String p : permitAll) {
			if (path.startsWith(p)) {
				return new Principal() {
					@Override
					public String getName() {
						return "anonymous";
					}
				};
			}
		}

		String cookie = parseCookie(exchange.getRequestHeaders().getFirst("Cookie"));
		principal = getSessionFrom(cookie);
		if (principal == null) {
			final String[] credentials = getCredentials(exchange);

			if (credentials != null) {
				boolean isLocal = isLocal(exchange);
				if (isLocal || authMode == AuthMode.BASIC_NOVERIFY) {
					principal = new Principal() {
						@Override
						public String getName() {
							return credentials[0];
						}
					};
				} else if (!isLocal && authMode == AuthMode.BASIC) {
					principal = verifyCredentials(credentials);
					cookie = createSessionFor(principal);
				}
			}

			if (principal == null) {
				String query = null, token = null;
				String referer = exchange.getRequestHeaders().getFirst("Referer");
				if (referer != null)
					query = URI.create(referer).getQuery();
				if (query == null)
					query = exchange.getRequestURI().getQuery();
				if (query != null)
					token = Authorization.getToken(query);
				if (token == null) {
					if (authMode == AuthMode.MICA && credentials != null && credentials.length == 2) {
						token = Authorization.getToken(credentials[0], encode(credentials[1]));
					}
				}
				if (token != null)
					principal = Authorization.getPrincipal(token);
				if (principal == null) {
					String agent = exchange.getRequestHeaders().getFirst("User-agent");
					if (authMode.isBasic() || agent != null && agent.contains("Gecko")) {
						exchange.getResponseHeaders().set("WWW-Authenticate", "Basic realm=\"Menucha\"");
						return null;
					}
				}
				cookie = createSessionFor(principal);
			}
		}
		if (cookie != null)
			exchange.getResponseHeaders().set("Set-Cookie", cookie + ";Max-Age=86400;Path=/" + hostname + ";SameSite=Lax");
		return principal;
	}

	private static String parseCookie(String cookieFromHeader) {
		if (cookieFromHeader != null) {
			String[] cookies = cookieFromHeader.split(";");
			for (String cookie : cookies) {
				String c = cookie.trim();
				if (c.startsWith(COOKIE_KEY))
					return c;
			}
		}
		return cookieFromHeader;
	}

	private static String createSessionFor(Principal principal) {
		String cookie = null;
		if (principal != null) {
			cookie = COOKIE_KEY + "=" + UUID.randomUUID();
			synchronized (sessions) {
				if (sessions.size() > 10)
					sessions.remove(sessions.keySet().iterator().next());
				sessions.put(cookie, principal);
			}
		}
		return cookie;
	}

	private static Principal getSessionFrom(String cookie) {
		Principal principal = null;
		if (cookie != null) {
			synchronized (sessions) {
				principal = sessions.get(cookie);
			}
		}
		return principal;
	}

	private static Principal verifyCredentials(final String[] credentials) {
		if (credentials != null && credentials.length == 2 && credentials[1] != null && credentials[1].length() > 0) {
			ProcessBuilder builder = new ProcessBuilder(VERIFY_BASIC_CREDENTIALS_COMMAND, credentials[0]);
			try {
				Process process = builder.start();
				try (Writer writer = new BufferedWriter(new OutputStreamWriter(process.getOutputStream()))) {
					writer.write(credentials[1]);
					writer.flush();
				}
				int exitValue = process.waitFor();
				switch (exitValue) {
				case 0: // authenticated
					return new Principal() {
						@Override
						public String getName() {
							return credentials[0];
						}
					};
				case 1: // not authenticated
					break;
				default:
					log.log(Level.FINE, "Failed to verify credentials with " + VERIFY_BASIC_CREDENTIALS_COMMAND + ": exited with unexpected exit value "
							+ exitValue);
					break;
				}
			} catch (IOException e) {
				log.log(Level.FINE, "Failed to verify credentials with " + VERIFY_BASIC_CREDENTIALS_COMMAND + ": " + e.getMessage());
			} catch (InterruptedException e) {
				// ignore
			}
		}
		return null;
	}
}