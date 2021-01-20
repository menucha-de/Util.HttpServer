package havis.net.server.http;

import java.io.Serializable;

/**
 * Container for a response message
 * 
 */
public class Response implements Serializable {

	private static final long serialVersionUID = 1L;

	String jsonrpc;
	int id;
	Object error;
	int code;
	Object[] result;

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
	 * Gets the response id
	 * 
	 * @return The response id
	 */
	public int getId() {
		return id;
	}

	/**
	 * Sets the response id
	 * 
	 * @param id
	 *            The response id
	 */
	public void setId(int id) {
		this.id = id;
	}

	/**
	 * Gets the response error
	 * 
	 * @return The response error
	 */
	public Object getError() {
		return error;
	}

	/**
	 * Sets the response error
	 * 
	 * @param error
	 *            The response error
	 */
	public void setError(Object error) {
		this.error = error;
	}

	/**
	 * Gets the result objects
	 * 
	 * @return The result objects
	 */
	public Object[] getResult() {
		return result;
	}

	/**
	 * Sets the result objects
	 * 
	 * @param result
	 *            The result objects
	 */
	public void setResult(Object[] result) {
		this.result = result;
	}
}
