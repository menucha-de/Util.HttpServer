package havis.net.server.http;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Scanner;
import java.util.Set;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Application;
import javax.xml.bind.DatatypeConverter;

import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

public class HttpServiceTest {

	@BeforeClass
	public static void init() {
		System.setProperty(Authorization.BASIC, "true");
		System.setProperty(HttpService.ROOT, "target/test/www");
	}

	@Path("/test1")
	public static class SimpleResource1 {
		@GET
		@Produces("text/plain")
		public String get() {
			return "hello world 1";
		}

	}

	@Path("/test2")
	public static class SimpleResource2 {
		@GET
		@Produces("text/plain")
		public String get() {
			return "hello world 2";
		}

	}

	@Path("/test3")
	public static class SimpleResource3 {
		@GET
		@Produces("text/plain")
		public String get() {
			return "hello world 3";
		}

	}

	//@Test
	public void test() throws IOException {
		HttpService httpService = new HttpService();
		httpService.start();
		try {

			Application application1 = new Application() {
				@Override
				public Set<Class<?>> getClasses() {
					return new HashSet<Class<?>>(Arrays.asList(new Class<?>[] { SimpleResource1.class, SimpleResource2.class }));
				}
			};
			httpService.add(application1);

			try (Scanner scanner = new Scanner(System.in)) {
				System.out.println("1");
				System.out.println(scanner.next());

				Application application2 = new Application() {
					@Override
					public Set<Object> getSingletons() {
						return new HashSet<Object>(Arrays.asList(new Object[] { new SimpleResource3() }));
					}
				};
				httpService.add(application2);

				System.out.println("2");
				System.out.println(scanner.next());
			}
		} finally {
			httpService.stop();
		}
	}

	private void get(String spec) throws IOException {
		byte[] bytes = new byte[65335];
		URL url = new URL(spec);
		HttpURLConnection connection = (HttpURLConnection) url.openConnection();
		connection.setRequestProperty("Authorization", "Basic " + DatatypeConverter.printBase64Binary("admin:admin".getBytes()));
		try (InputStream stream = connection.getInputStream()) {
			stream.read(bytes);
		}
	}

	@Test
	public void accessTest() throws IOException {
		new File("target/test/www/new").mkdirs();
		new File("target/test/www/test1").createNewFile();
		new File("target/test/www/new/test2").createNewFile();
		new File("target/test/test3").createNewFile();
		HttpService httpService = new HttpService();
		httpService.start();
		try {
			try {
				get("http://localhost:8080/../test3");
				Assert.fail();
			} catch (IOException e) {
				Assert.assertEquals("Server returned HTTP response code: 403 for URL: http://localhost:8080/../test3", e.getMessage());
			}
			get("http://localhost:8080/new/test2");
			get("http://localhost:8080/new/../test1");
			get("http://localhost:8080/test1");
		} finally {
			httpService.stop();
		}
	}
}
