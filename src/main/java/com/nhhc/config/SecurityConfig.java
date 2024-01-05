package com.nhhc.config;

import com.nhhc.AppConfig;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.springframework.boot.web.embedded.jetty.JettyServletWebServerFactory;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .requiresChannel()
                .antMatchers("/CARootCert/**").requiresInsecure() // /test接口可以通过HTTP或HTTPS访问
                .antMatchers("/test/**").requiresSecure(); // 其他接口必须通过HTTPS访问
        return http.build();
    }

    /*@Bean
    public WebServerFactoryCustomizer<JettyServletWebServerFactory> jettyCustomizer(AppConfig config) {
        return factory -> {
            // Configure HTTP connector
            factory.addServerCustomizers(server -> {
                ServerConnector connector = new ServerConnector(server);
                connector.setPort(8080);
                server.addConnector(connector);
            });

            // Configure HTTPS connector
            factory.addServerCustomizers(new ServerCustomizer(config));
        };
    }*/
}
