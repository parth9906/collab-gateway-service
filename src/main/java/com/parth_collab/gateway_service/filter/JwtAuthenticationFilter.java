package com.parth_collab.gateway_service.filter;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.security.Key;

@Component
public class JwtAuthenticationFilter implements WebFilter {

    @Value("${jwt.secret}")
    private String jwtSecret;

    private Key key;

    @PostConstruct
    public void init() {
        this.key = Keys.hmacShaKeyFor(jwtSecret.getBytes());
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String path = exchange.getRequest().getURI().getPath();

        if (HttpMethod.OPTIONS.equals(exchange.getRequest().getMethod()) || path.startsWith("/api/auth/")) {
            addCorsHeaders(exchange);
            return chain.filter(exchange);
        }

        String authHeader = exchange.getRequest().getHeaders().getFirst("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            addCorsHeaders(exchange);
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }
        String token = authHeader.substring(7);


        try {
            Jws<Claims> claimsJws = Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(token);
            Claims claims = claimsJws.getBody();

            exchange = exchange.mutate()
                    .request(exchange.getRequest().mutate()
                            .header("X-User-Id", claims.get("id", String.class))
                            .header("X-User-Role", claims.get("role", String.class))
                            .header("X-Username", claims.get("username", String.class))
                            .header("X-Email", claims.get("email", String.class))
                            .build())
                    .build();

            addCorsHeaders(exchange); // ensure CORS headers for valid requests
            return chain.filter(exchange);

        } catch (JwtException e) {
            addCorsHeaders(exchange);
            exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
            return exchange.getResponse().setComplete();
        }
    }

    // Add CORS headers to every response
    private void addCorsHeaders(ServerWebExchange exchange) {
        exchange.getResponse().getHeaders().add("Access-Control-Allow-Origin", "http://localhost:5173");
        exchange.getResponse().getHeaders().add("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS");
        exchange.getResponse().getHeaders().add("Access-Control-Allow-Headers", "Authorization,Content-Type,X-User-Id,X-User-Role");
        exchange.getResponse().getHeaders().add("Access-Control-Allow-Credentials", "true");
    }
}
