package havis.net.server.http;

import java.io.Serializable;

/**
 * Container for a request message
 * 
 */
public class Request implements Serializable {

	private static final long serialVersionUID = 1L;

	private String jsonrpc = "2.0";
	private int id;
	private String method;
	private Object[] params;

	@SafeVarargs
	public Request(int id, String method, Object... params) {
		this.id = id;
		this.method = method;
		this.params = params;
	}

	/**
	 * Gets the JSON-RPC protocol version
	 * 
	 * @return The version
	 */
	public String getJsonrpc() {
		return jsonrpc;
	}

	/**
	 * Sets the JSON-RPC protocol version
	 * 
	 * @param jsonrpc
	 *            The version
	 */
	public void setJsonrpc(String jsonrpc) {
		this.jsonrpc = jsonrpc;
	}

	/**
	 * Gets the request id
	 * 
	 * @return The request id
	 */
	public int getId() {
		return id;
	}

	/**
	 * Sets the request id
	 * 
	 * @param id
	 *            The request id
	 */
	public void setId(int id) {
		this.id = id;
	}

	/**
	 * Gets the request method
	 * 
	 * @return The request method
	 */
	public String getMethod() {
		return method;
	}

	/**
	 * Sets the request method
	 * 
	 * @param method
	 *            The request method
	 */
	public void setMethod(String method) {
		this.method = method;
	}

	/**
	 * Gets the request parameters
	 * 
	 * @return The request parameters
	 */
	public Object[] getParams() {
		return params;
	}

	/**
	 * Sets the request parameters
	 * 
	 * @param params
	 *            The request parameters
	 */
	public void setParams(Object[] params) {
		this.params = params;
	}
}
