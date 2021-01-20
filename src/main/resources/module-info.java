module havis.net.server.http {
    requires jackson.databind;
    requires java.logging;
    requires jaxb.api;
    requires resteasy.jaxrs;
    requires resteasy.jdk.http;

    requires transitive javax.annotation.api;
    requires transitive javax.ws.rs.api;
    requires transitive jdk.httpserver;
    requires transitive resteasy.jackson2.provider;
    requires transitive resteasy.jaxb.provider;

    exports havis.net.server.http;
    exports havis.net.server.http.provider;

}