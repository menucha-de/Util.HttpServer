package havis.net.server.http.provider;

import java.io.IOException;
import java.lang.reflect.Method;

import javax.annotation.security.RolesAllowed;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.container.ResourceInfo;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;
import javax.ws.rs.core.SecurityContext;
import javax.ws.rs.ext.Provider;

@Provider
public class AuthenticationRequestFilter implements ContainerRequestFilter {

	@Context
	public ResourceInfo resourceInfo;

	@Override
	public void filter(ContainerRequestContext requestContext)
			throws IOException {
		Method method = resourceInfo.getResourceMethod();
		SecurityContext sc = requestContext.getSecurityContext();

		if (method.isAnnotationPresent(RolesAllowed.class)) {
			boolean userInRole = false;
			RolesAllowed rolesAnnotation = method
					.getAnnotation(RolesAllowed.class);
			for (String role : rolesAnnotation.value()) {
				if (sc.isUserInRole(role)) {
					userInRole = true;
					break;
				}
			}
			if (!userInRole) {
				requestContext.abortWith(Response
						.status(Status.UNAUTHORIZED)
						.entity("Access denied for this resource.")
						.type(MediaType.TEXT_PLAIN).build());
				return;
			}
		}
	}

}
