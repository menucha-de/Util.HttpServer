package havis.net.server.http;

import java.util.logging.Level;
import java.util.logging.Logger;

import javax.ws.rs.core.Application;

import org.osgi.framework.BundleActivator;
import org.osgi.framework.BundleContext;
import org.osgi.framework.ServiceReference;
import org.osgi.util.tracker.ServiceTracker;

/**
 * Implements the activator for HTTP REST application
 * 
 */
public class Activator implements BundleActivator {

	private final static Logger logger = Logger.getLogger(Activator.class.getName());

	ServiceTracker<Application, Application> tracker;
	ServiceTracker<ClassLoader, ClassLoader> contextTracker;
	HttpService httpService;

	/**
	 * Starts the bundle. Creates and starts a {@link HttpService} instance.
	 * Adds and open a {@link Application} {@link ServiceTracker}.
	 */
	@Override
	public void start(BundleContext context) throws Exception {
		httpService = new HttpService();
		logger.log(Level.FINE, "Starting service {0}.", httpService.getClass().getName());
		httpService.start();
		tracker = new ServiceTracker<Application, Application>(context, Application.class, null) {

			@Override
			public Application addingService(ServiceReference<Application> reference) {
				Application application = super.addingService(reference);
				logger.log(Level.FINE, "Adding application {0} to service {1}.", new Object[] { application.getClass().getName(),
						httpService.getClass().getName() });
				httpService.add(application);
				return application;
			}

			@Override
			public void removedService(ServiceReference<Application> reference, Application service) {
				logger.log(Level.FINE, "Removing application {0} from service {1}.", new Object[] { service.getClass().getName(),
						httpService.getClass().getName() });
				httpService.remove(service);
				super.removedService(reference, service);
			}
		};
		logger.log(Level.FINE, "Opening tracker {0}.", tracker.getClass().getName());
		tracker.open();

		contextTracker = new ServiceTracker<ClassLoader, ClassLoader>(context, ClassLoader.class, null) {
			@Override
			public ClassLoader addingService(ServiceReference<ClassLoader> reference) {
				return httpService.classLoader = super.addingService(reference);
			}

			@Override
			public void removedService(ServiceReference<ClassLoader> reference, ClassLoader service) {
				httpService.classLoader = null;
				super.removedService(reference, service);
			}
		};
		contextTracker.open();
	}

	/**
	 * Stops the bundle. Closes the {@link ServiceTracker}. Stops the
	 * {@link HttpService}.
	 */
	@Override
	public void stop(BundleContext context) throws Exception {
		logger.log(Level.FINE, "Closing tracker {0}.", tracker.getClass().getName());
		tracker.close();
		logger.log(Level.FINE, "Stopping service {0}.", httpService.getClass().getName());
		httpService.stop();
	}
}