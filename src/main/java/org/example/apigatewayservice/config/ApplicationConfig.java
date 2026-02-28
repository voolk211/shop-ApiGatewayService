package org.example.apigatewayservice.config;

import lombok.RequiredArgsConstructor;
import org.springframework.cloud.gateway.filter.ratelimit.KeyResolver;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import reactor.core.publisher.Mono;

import java.net.InetAddress;
import java.net.InetSocketAddress;


//@RequiredArgsConstructor
//@EnableWebSecurity
@Configuration
public class ApplicationConfig {

    @Bean
    public KeyResolver ipKeyResolver() {
        return exchange ->
                Mono.justOrEmpty(exchange.getRequest().getRemoteAddress())
                .map(InetSocketAddress::getAddress)
                .map(InetAddress::getHostAddress)
                .defaultIfEmpty("unknown");
    }
}
