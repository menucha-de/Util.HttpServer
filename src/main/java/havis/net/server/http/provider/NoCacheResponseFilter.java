package havis.net.server.http.provider;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerResponseContext;
import javax.ws.rs.container.ContainerResponseFilter;
import javax.ws.rs.ext.Provider;

@Provider
public class NoCacheResponseFilter implements ContainerResponseFilter {

	@Override
	public void filter(ContainerRequestContext requestContext,
			ContainerResponseContext responseContext) throws IOException {
		if (requestContext.getMethod().equals("GET")) {
			List<Object> cachecontrol = new ArrayList<>();
			cachecontrol.add("no-cache");
			responseContext.getHeaders().put("Cache-Control", cachecontrol);
		}
	}

}
