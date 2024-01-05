package com.nhhc;

import com.nhhc.config.ServerCustomizer;
import com.tencent.kona.KonaProvider;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.web.embedded.jetty.JettyServletWebServerFactory;
import org.springframework.boot.web.servlet.server.ConfigurableServletWebServerFactory;
import org.springframework.context.annotation.Bean;

import java.security.Security;

@SpringBootApplication
public class JettyServer {

    static {
        Security.addProvider(new KonaProvider());
    }

    public static void main(String[] args) {
//        System.setProperty("com.tencent.kona.ssl.debug", "all");
        SpringApplication.run(JettyServer.class, args);
    }

    @Bean
    public ConfigurableServletWebServerFactory webServerFactory(AppConfig config) {
        JettyServletWebServerFactory factory = new JettyServletWebServerFactory();
        factory.addServerCustomizers(new ServerCustomizer(config));
        return factory;
    }

}
