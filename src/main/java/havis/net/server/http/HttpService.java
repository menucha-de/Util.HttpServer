package havis.net.server.http;

import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLConnection;
import java.nio.file.Files;
import java.security.Principal;
import java.util.Map.Entry;
import java.util.concurrent.Executors;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.ws.rs.core.Application;
import javax.ws.rs.core.SecurityContext;
import javax.ws.rs.ext.RuntimeDelegate;

import org.jboss.resteasy.plugins.server.sun.http.HttpContextBuilder;
import org.jboss.resteasy.spi.Registry;
import org.jboss.resteasy.spi.ResteasyProviderFactory;
import org.jboss.resteasy.spi.metadata.ResourceBuilder;
import org.jboss.resteasy.util.HttpResponseCodes;

import com.sun.net.httpserver.Filter;
import com.sun.net.httpserver.HttpContext;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

/**
 * Implements a HTTP service
 * 
 */
public class HttpService implements HttpHandler {

	public static final String PORT = "havis.net.server.http.port";
	public static final String ROOT = "havis.net.server.http.root";
	public static final String PATH = "havis.net.server.http.path";

	private int port = 8080;
	private String path = "rest";
	private String root = "www";

	private final static Logger log = Logger.getLogger(HttpService.class.getName());

	private HttpServer httpServer;
	private HttpContextBuilder builder = new HttpContextBuilder();
	private HttpContext context;

	ClassLoader classLoader;

	/**
	 * Creates a new instance. Sets the port {@value PORT} for
	 * {@link HttpServer} and path {@value PATH} for {@link HttpContextBuilder},
	 * if one of that is given by system property
	 * 
	 * @throws IOException
	 */
	public HttpService() {
		String port = System.getProperty(PORT);
		if (port != null) {
			log.log(Level.FINE, "Changing default port of http server to {0}.", port);
			this.port = Integer.parseInt(port);
		}

		String root = System.getProperty(ROOT);
		if (root != null) {
			log.log(Level.FINE, "Setting root directory of http server to {0}.", root);
			this.root = root;
		}

		String path = System.getProperty(PATH);
		if (path != null && !(path = path.trim()).isEmpty()) {
			if ((path = path.trim()).isEmpty()) {
				log.log(Level.FINE, "Could't set path to empty string");
			} else {
				log.log(Level.FINE, "Setting path of context builder {0} to {1}.", new Object[] { builder.getClass().getName(), path });
				this.path = path;
			}
		}
		builder.setPath(this.path);

		ClassLoader current = Thread.currentThread().getContextClassLoader();
		try {
			Thread.currentThread().setContextClassLoader(getClass().getClassLoader());
			RuntimeDelegate.getInstance();
		} finally {
			Thread.currentThread().setContextClassLoader(current);
		}
	}

	/**
	 * Adds the given application. Adds all classes and singletons to registry
	 * and applies the given properties.
	 * 
	 * @param application
	 *            The application
	 */
	public void add(Application application) {
		synchronized (this) {
			if (builder != null) {
				Registry registry = builder.getDeployment().getRegistry();
				if (application.getClasses() != null) {
					for (Class<?> clazz : application.getClasses()) {
						log.log(Level.FINE, "Adding class resource {0} from Application {1}.",
								new Object[] { clazz.getName(), application.getClass().getName() });
						registry.addPerRequestResource(clazz);
					}
				}
				if (application.getSingletons() != null) {
					for (Object obj : application.getSingletons()) {
						log.log(Level.FINE, "Adding singleton resource {0} from Application {1}.", new Object[] { obj.getClass().getName(),
								application.getClass().getName() });
						registry.addSingletonResource(obj, ResourceBuilder.rootResourceFromAnnotations(obj.getClass()));
					}
				}
				if (application.getProperties() != null) {
					for (Entry<String, Object> entry : application.getProperties().entrySet()) {
						switch (entry.getKey()) {
						case "javax.ws.rs.ext.Providers":
							if (entry.getValue() instanceof Class<?>[])
								for (Class<?> provider : (Class<?>[]) entry.getValue()) {
									log.log(Level.FINE, "Adding provider ''{0}''.", provider.getName());
									builder.getDeployment().getProviderFactory().registerProvider(provider);
								}
							else
								log.warning("Providers property value must be a class array");
							break;
						case "javax.annotation.security.PermitAll":
							if (entry.getValue() instanceof String[]) {
								Authorization.addPermitAll((String[]) entry.getValue());
								log.log(Level.FINE, "Adding permit all to ''{0}''.", entry.getValue());
							} else
								log.warning("PermitAll property value must be a string array");
							break;
						default:
							context.getAttributes().put(entry.getKey(), entry.getValue());
							break;

						}

					}
				}
			}
		}
	}

	/**
	 * Removes the given application. Removes all classes and singletons from
	 * registry.
	 * 
	 * @param application
	 *            The application
	 */
	public void remove(Application application) {
		synchronized (this) {
			if (builder != null) {
				Registry registry = builder.getDeployment().getRegistry();
				if (application.getClasses() != null) {
					for (Class<?> clazz : application.getClasses()) {
						log.log(Level.FINE, "Removing class resource {0} from application {1}.", new Object[] { clazz.getName(),
								application.getClass().getName() });
						registry.removeRegistrations(clazz);
					}
				}
				if (application.getSingletons() != null) {
					for (Object obj : application.getSingletons()) {
						log.log(Level.FINE, "Removing singleton resource {0} from application {1}.", new Object[] { obj.getClass().getName(),
								application.getClass().getName() });
						registry.removeRegistrations(obj.getClass());
					}
				}
			}
		}
	}

	private String mime(String name) {
		String mime = URLConnection.guessContentTypeFromName(name);
		if (mime == null) {
			int index = name.lastIndexOf('.');
			if (index > -1) {
				switch (name.substring(index + 1)) {
				case "css":
					return "text/css";
				case "js":
					return "application/x-javascript";
				case "svg":
					return "image/svg+xml";
				}
			}
		}
		return mime;
	}

	private File file(URI uri) throws IOException {
		File file = new File(root, uri.getPath());
		if (file.getCanonicalPath().startsWith(new File(root).getCanonicalPath())) {
			if (file.isDirectory())
				file = new File(file, "index.html");
			return file;
		} else {
			throw new SecurityException("File isn't in document root folder");
		}
	}

	@Override
	public void handle(HttpExchange exchange) throws IOException {
		try {
			File file = file(exchange.getRequestURI());
			String name = file.getName();

			String mime = mime(name);
			if (mime != null)
				exchange.getResponseHeaders().set("Content-Type", mime);

			if (file.isFile()) {
				try {

					exchange.sendResponseHeaders(HttpResponseCodes.SC_OK, 0);
					if (log.isLoggable(Level.FINE))
						log.log(Level.FINE, "Reading file {0}", file.getAbsoluteFile());
					OutputStream stream = exchange.getResponseBody();
					Files.copy(file.toPath(), stream);
					stream.close();

				} catch (IOException e) {
					exchange.sendResponseHeaders(HttpResponseCodes.SC_INTERNAL_SERVER_ERROR, -1);
				}
			} else {
				exchange.sendResponseHeaders(HttpResponseCodes.SC_NOT_FOUND, -1);
			}
		} catch (SecurityException e) {
			exchange.sendResponseHeaders(HttpResponseCodes.SC_FORBIDDEN, -1);
		}
	}

	private Filter filter() {
		return new Filter() {

			@Override
			public void doFilter(HttpExchange exchange, Chain chain) throws IOException {
				try {
					if (CorsHandler.handle(exchange))
						return;

					final Principal principal = Authorization.getPrincipal(exchange);

					if (principal != null) {
						SecurityContext securityContext = new SecurityContext() {

							@Override
							public Principal getUserPrincipal() {
								return principal;
							}

							@Override
							public boolean isUserInRole(String role) {
								return role != null && role.equals(principal.getName());
							}

							@Override
							public boolean isSecure() {
								return true;
							}

							@Override
							public String getAuthenticationScheme() {
								return SecurityContext.BASIC_AUTH;
							}
						};

						try {
							ResteasyProviderFactory.pushContext(SecurityContext.class, securityContext);
							ClassLoader current = Thread.currentThread().getContextClassLoader();
							try {
								Thread.currentThread().setContextClassLoader(classLoader != null ? classLoader : getClass().getClassLoader());
								chain.doFilter(exchange);
							} finally {
								Thread.currentThread().setContextClassLoader(current);
							}
						} finally {
							ResteasyProviderFactory.clearContextData();
						}
					} else {
						exchange.sendResponseHeaders(HttpResponseCodes.SC_UNAUTHORIZED, -1);
					}
				} catch (Exception e) {
					log.log(Level.FINE, "Internal server error", e);
					exchange.sendResponseHeaders(HttpResponseCodes.SC_INTERNAL_SERVER_ERROR, -1);
				}
			}

			@Override
			public String description() {
				return null;
			}

		};
	}

	/**
	 * Starts the service. Create an new {@link HttpServer} instance on first
	 * run. Binds the {@link HttpContextBuilder} to server.Adds a new
	 * {@link Filter}.
	 */
	public void start() {
		synchronized (this) {

			Filter filter = filter();

			if (httpServer == null) {
				try {
					log.log(Level.FINE, "Creating http server on port {0,number,#}.", port);
					httpServer = HttpServer.create(new InetSocketAddress(this.port), 0);
					httpServer.setExecutor(Executors.newCachedThreadPool());
					httpServer.createContext("/", this).getFilters().add(new Filter() {
						@Override
						public void doFilter(HttpExchange exchange, Chain chain) throws IOException {
							if (Authorization.getPrincipal(exchange) == null) {
								exchange.sendResponseHeaders(HttpResponseCodes.SC_UNAUTHORIZED, -1);
							} else {
								chain.doFilter(exchange);
							}
						}

						@Override
						public String description() {
							return null;
						}
					});
				} catch (IOException e) {
					throw new RuntimeException(e);
				}
			}

			log.log(Level.FINE, "Binding context builder {0} to http server {1}.",
					new Object[] { builder.getClass().getName(), httpServer.getClass().getName() });

			ClassLoader current = Thread.currentThread().getContextClassLoader();
			try {
				Thread.currentThread().setContextClassLoader(getClass().getClassLoader());
				context = builder.bind(httpServer);
			} finally {
				Thread.currentThread().setContextClassLoader(current);
			}

			log.log(Level.FINE, "Adding filter to context {0}.", context.getClass().getName());
			context.getFilters().add(filter);

			httpServer.start();
		}
	}

	/**
	 * Stops the {@link HttpServer}. Cleans up the {@link HttpContextBuilder}.
	 */
	public void stop() {
		synchronized (this) {
			if (httpServer != null) {
				log.log(Level.FINE, "Stopping http server {0}.", httpServer.getClass().getName());
				httpServer.stop(0);
			}

			log.log(Level.FINE, "Cleaning up context builder {0}.", builder.getClass().getName());
			builder.cleanup();
		}
	}

	public static HttpService create(Application... applications) {
		log.info("Creating http server");
		HttpService httpService = new HttpService();

		log.info("Starting http server");
		httpService.start();

		for (Application application : applications) {
			log.log(Level.INFO, "Adding http server ''{0}'' application", application.getClass().getName());
			httpService.add(application);
		}

		return httpService;
	}
}