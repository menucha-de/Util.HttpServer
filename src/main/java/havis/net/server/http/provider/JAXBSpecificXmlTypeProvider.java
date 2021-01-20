package havis.net.server.http.provider;

import java.io.IOException;
import java.io.OutputStream;
import java.lang.annotation.Annotation;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Type;

import javax.ws.rs.Consumes;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.ext.Provider;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;

import org.jboss.resteasy.plugins.providers.jaxb.JAXBMarshalException;
import org.jboss.resteasy.plugins.providers.jaxb.JAXBXmlTypeProvider;

/**
 * Improved version of {@link JAXBXmlTypeProvider}.
 * 
 * @see JAXBXmlTypeProvider
 */
@Provider
@Produces({ "application/*+xml", "text/*+xml" })
@Consumes({ "application/*+xml", "text/*+xml" })
public class JAXBSpecificXmlTypeProvider extends JAXBXmlTypeProvider {

	@Override
	public void writeTo(Object t, Class<?> type, Type genericType, Annotation[] annotations, MediaType mediaType, MultivaluedMap<String, Object> httpHeaders,
			OutputStream entityStream) throws IOException {
		JAXBElement<?> result = wrap(t, type);
		// code from AbstractJAXBProvider
		try {
			Marshaller marshaller = getMarshaller(type, annotations, mediaType);
			marshaller = decorateMarshaller(type, annotations, mediaType, marshaller);
			marshaller.marshal(result, entityStream);
		} catch (JAXBException e) {
			throw new JAXBMarshalException(e);
		}
	}

	private JAXBElement<?> wrap(Object t, Class<?> type) {
		try {
			Object factory = findObjectFactory(type);
			String createMethod = "create" + type.getSimpleName();
			Method[] method = factory.getClass().getDeclaredMethods();
			for (int i = 0; i < method.length; i++) {
				Method current = method[i];
				if (current.getParameterTypes().length == 1 && current.getParameterTypes()[0].equals(type) && current.getName().equals(createMethod)) {
					Object result = current.invoke(factory, new Object[] { t });
					return JAXBElement.class.cast(result);
				}
			}
			throw new JAXBMarshalException(String.format("The method %s() " + "was not found in the object Factory!", createMethod));
		} catch (IllegalArgumentException e) {
			throw new JAXBMarshalException(e);
		} catch (IllegalAccessException e) {
			throw new JAXBMarshalException(e);
		} catch (InvocationTargetException e) {
			throw new JAXBMarshalException(e.getCause());
		}
	}
}
