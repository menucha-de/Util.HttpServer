package havis.net.server.http;

import java.io.IOException;

import javax.ws.rs.HttpMethod;

import org.jboss.resteasy.spi.CorsHeaders;
import org.jboss.resteasy.util.HttpResponseCodes;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;

/**
 * Cross-origin resource sharing handler to allow access from other domains
 */
public class CorsHandler {

	private static void respond(HttpExchange exchange) throws IOException {
		Headers headers = exchange.getResponseHeaders();
		headers.set(CorsHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, "*");
		headers.set(CorsHeaders.ACCESS_CONTROL_ALLOW_CREDENTIALS, Boolean.TRUE.toString());
		headers.set(CorsHeaders.ACCESS_CONTROL_ALLOW_METHODS, exchange.getRequestHeaders().getFirst(CorsHeaders.ACCESS_CONTROL_REQUEST_METHOD));
		headers.set(CorsHeaders.ACCESS_CONTROL_ALLOW_HEADERS, exchange.getRequestHeaders().getFirst(CorsHeaders.ACCESS_CONTROL_REQUEST_HEADERS));
		exchange.sendResponseHeaders(HttpResponseCodes.SC_OK, -1);
	}

	/**
	 * Handle CORS request
	 * 
	 * @param exchange
	 *            the HTTP exchange
	 * @return true if the request was handled and no further action is
	 *         required, false otherwise
	 * @throws IOException
	 */
	public static boolean handle(HttpExchange exchange) throws IOException {
		// handle CORS OPTIONS request
		if (exchange.getRequestHeaders().getFirst(CorsHeaders.ORIGIN) != null
				&& exchange.getRequestMethod().equalsIgnoreCase(HttpMethod.OPTIONS)
				&& (exchange.getRequestHeaders().containsKey(CorsHeaders.ACCESS_CONTROL_REQUEST_METHOD)
				 || exchange.getRequestHeaders().containsKey(CorsHeaders.ACCESS_CONTROL_REQUEST_HEADERS))) {
			respond(exchange);
			return true;
		}

		// All following requests must also have the "*-Allow-*" headers set if
		// an "Origin" is sent. To avoid a bug with older browsers not sending
		// the "Origin", we simply always set the headers, see:
		// https://bugs.webkit.org/show_bug.cgi?id=50773
		if (!exchange.getRequestMethod().equalsIgnoreCase(HttpMethod.OPTIONS)) {
			Headers headers = exchange.getResponseHeaders();
			headers.set(CorsHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, "*");
			headers.set(CorsHeaders.ACCESS_CONTROL_ALLOW_CREDENTIALS, Boolean.TRUE.toString());
		}

		return false;
	}
}
