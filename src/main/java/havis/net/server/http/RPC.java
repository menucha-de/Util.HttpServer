package havis.net.server.http;

import java.io.BufferedReader;
import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.Reader;
import java.io.UnsupportedEncodingException;
import java.util.Map;
import java.util.Timer;
import java.util.TimerTask;
import java.util.logging.Level;
import java.util.logging.Logger;

import com.fasterxml.jackson.databind.ObjectMapper;

public class RPC implements Closeable {

	private final static Logger log = Logger.getLogger(Authorization.class.getName());
	private final static String URL = "https://mica/ws/";
	private final static ObjectMapper mapper = new ObjectMapper();

	private Process process;
	private Timer timer;

	public RPC() throws IOException {
		this("mica-rpc", URL);
	}

	public RPC(String... command) throws IOException {
		process = new ProcessBuilder(command).start();
		timer = new Timer();
		timer.schedule(new TimerTask() {
			@Override
			public void run() {
				try {
					log.info(RPC.this.<String> invoke("ping"));
				} catch (Exception e) {
				}
			}
		}, 15000, 15000);
	}

	private static void log(InputStream input) throws UnsupportedEncodingException, IOException {
		if (log.isLoggable(Level.FINE)) {
			StringBuilder builder = new StringBuilder();
			int size = input.available();
			if (size > 0) {
				char[] b = new char[size];
				Reader reader = new InputStreamReader(input);
				reader.read(b);
				builder.append(b);
			}
			log.fine(builder.toString());
		}
	}

	private static String read(InputStream input) throws UnsupportedEncodingException, IOException {
		return new BufferedReader(new InputStreamReader(input)).readLine();
	}

	private static void write(OutputStream output, String data) throws IOException {
		output.write(data.getBytes());
		output.flush();
	}

	public synchronized <T> T invoke(String method) throws Exception {
		return invoke(method, null);
	}

	@SuppressWarnings("unchecked")
	public synchronized <T> T invoke(String method, Object params) throws Exception {
		StringBuilder builder = new StringBuilder();
		builder.append("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"").append(method).append("\"");
		if (params != null)
			builder.append(",\"params\":").append(mapper.writeValueAsString(params));
		builder.append("}\n");
		write(process.getOutputStream(), builder.toString());
		log(process.getErrorStream());
		Map<String, Object> map = (Map<String, Object>) mapper.readValue(read(process.getInputStream()), Object.class);
		Object result = map.get("result");
		if (result != null)
			return (T) result;
		map = (Map<String, Object>) map.get("error");
		throw new Exception(map.get("code") + ": " + map.get("message"));
	}

	@Override
	public void close() {
		timer.cancel();
		try {
			process.getOutputStream().close();
			process.waitFor();
		} catch (Exception e) {
			log.log(Level.FINE, "Failed to terminate process", e);
		}
	}
}