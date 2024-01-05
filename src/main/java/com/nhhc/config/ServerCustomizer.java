package com.nhhc.config;

import com.nhhc.AppConfig;
import org.eclipse.jetty.http.HttpVersion;
import org.eclipse.jetty.server.*;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.springframework.boot.web.embedded.jetty.JettyServerCustomizer;
import org.springframework.util.ResourceUtils;

import javax.net.ssl.SSLParameters;
import java.io.FileNotFoundException;

public class ServerCustomizer implements JettyServerCustomizer {

    private final AppConfig appConfig;

    public ServerCustomizer(AppConfig appConfig) {
        this.appConfig = appConfig;
    }

    @Override
    public void customize(Server server) {
        SslContextFactory.Server contextFactory = new SslContextFactory.Server() {

            @Override
            public SSLParameters customize(SSLParameters sslParams) {
                return super.customize(sslParams);
            }
        };

        /*contextFactory.setTrustStoreProvider(appConfig.getTrustStoreProvider());
        contextFactory.setTrustStoreType(appConfig.getTrustStoreType());
        contextFactory.setTrustStorePath(getAbsolutePath(appConfig.getTrustStorePath()));
        contextFactory.setTrustStorePassword(appConfig.getTrustStorePassword());*/

        contextFactory.setKeyStoreProvider(appConfig.getKeyStoreProvider());
        contextFactory.setKeyStoreType(appConfig.getKeyStoreType());
        contextFactory.setKeyStorePath(getAbsolutePath(appConfig.getKeyStorePath()));
        contextFactory.setKeyStorePassword(appConfig.getKeyStorePassword());
        contextFactory.setKeyManagerPassword(appConfig.getKeyStorePassword());

        contextFactory.setProtocol(appConfig.getContextProtocol());

        HttpConfiguration httpsConfig = new HttpConfiguration();
        httpsConfig.setSecureScheme("https");
        httpsConfig.addCustomizer(new SecureRequestCustomizer());


        ServerConnector httpsConnector = new ServerConnector(server,
                new SslConnectionFactory(contextFactory, HttpVersion.HTTP_1_1.asString()),
                new HttpConnectionFactory(httpsConfig));
        httpsConnector.setPort(appConfig.getPort());
        ServerConnector httpConnector = new ServerConnector(server);
        httpConnector.setPort(8080);
        server.setConnectors(new Connector[]{httpsConnector, httpConnector});
        server.setStopAtShutdown(true);
    }

    private static String getAbsolutePath(String resourcePath) {
        try {
            return ResourceUtils.getFile(resourcePath).getAbsolutePath();
        } catch (FileNotFoundException e) {
            // Should not occur
            throw new IllegalStateException("Not found: " + resourcePath, e);
        }
    }
}
