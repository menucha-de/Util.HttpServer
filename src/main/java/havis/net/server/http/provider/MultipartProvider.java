package havis.net.server.http.provider;

import java.io.IOException;
import java.io.OutputStream;
import java.lang.annotation.Annotation;
import java.lang.reflect.Type;
import java.util.Iterator;
import java.util.UUID;

import javax.ws.rs.Produces;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.ext.MessageBodyWriter;
import javax.ws.rs.ext.Provider;
import javax.ws.rs.ext.Providers;

@Provider
@Produces("multipart/*")
public class MultipartProvider implements MessageBodyWriter<Iterator<Object>> {

	private final static String boundary = UUID.randomUUID().toString();

	@Context
	public Providers workers;

	@Override
	public boolean isWriteable(Class<?> type, Type genericType, Annotation[] annotations, MediaType mediaType) {
		return findAnnotation(annotations) != null;
	}

	private PartType findAnnotation(Annotation[] annotations) {
		for (Annotation annotation : annotations) {
			if (annotation instanceof PartType) {
				return (PartType) annotation;
			}
		}
		return null;
	}

	@Override
	public long getSize(Iterator<Object> iter, Class<?> type, Type genericType, Annotation[] annotations, MediaType mediaType) {
		return -1;
	}

	@Override
	@SuppressWarnings("unchecked")
	public void writeTo(Iterator<Object> iter, Class<?> type, Type genericType, Annotation[] annotations, MediaType mediaType,
			MultivaluedMap<String, Object> httpHeaders, OutputStream entityStream) throws IOException, WebApplicationException {
		PartType partType = findAnnotation(annotations);
		if (partType != null) {
			MediaType partMediaType = MediaType.valueOf(partType.value());
			httpHeaders.putSingle("Content-Type", mediaType + "; boundary=" + boundary);
			entityStream.write(("\r\n").getBytes());
			try {
				while (iter.hasNext()) {
					entityStream.write(("Content-Type: " + partMediaType + "\r\n\r\n").getBytes());
					Object entity = iter.next();

					Class<?> clazz = entity.getClass();
					@SuppressWarnings("rawtypes")
					MessageBodyWriter writer = workers.getMessageBodyWriter(clazz, null, null, partMediaType);
					writer.writeTo(entity, clazz, null, null, partMediaType, null, entityStream);

					entityStream.write(("\r\n--" + boundary + "\r\n").getBytes());
					entityStream.flush();
				}
			} finally {
				iter.remove();
			}
		}
	}
}