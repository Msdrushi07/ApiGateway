package com.gateway.filter;


import com.gateway.ApiGatewayApplication;
import com.gateway.jwt.jwtService;

import io.jsonwebtoken.Claims;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.client.RestTemplate;


@Component
public class AuthenticationFilter extends AbstractGatewayFilterFactory<AuthenticationFilter.Config> {

    private final ApiGatewayApplication apiGatewayApplication;

    @Autowired
    private RouteValidator validator;

    //    @Autowired
//    private RestTemplate template;
    @Autowired
    private jwtService jwtUtil;

    public AuthenticationFilter(ApiGatewayApplication apiGatewayApplication) {
        super(Config.class);
        this.apiGatewayApplication = apiGatewayApplication;
    }

    @Override
    public GatewayFilter apply(Config config) {
        return ((exchange, chain) -> {
            if (validator.isSecured.test(exchange.getRequest())) {
                //header contains token or not
                if (!exchange.getRequest().getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
                    throw new RuntimeException("missing authorization header");
                }

                String authHeader = exchange.getRequest().getHeaders().get(HttpHeaders.AUTHORIZATION).get(0);
                if (authHeader != null && authHeader.startsWith("Bearer ")) {
                    authHeader = authHeader.substring(7);
                }
                try {
//                    //REST call to AUTH service
//                    template.getForObject("http://IDENTITY-SERVICE//validate?token" + authHeader, String.class);
                    Claims claims=jwtUtil.extractAllClaims(authHeader);  // here if we have claims after .parseClaimsJws(token) then token is valid or trusted
                    String username=claims.getSubject();
            		String[] res=claims.get("roles",String[].class);
            			List<String> listOfRoles=Arrays.asList(res);
            			List<GrantedAuthority> authorities=listOfRoles.stream().map(role -> new SimpleGrantedAuthority(role)).collect(Collectors.toList());
   // buliding an authentication object by providing username,roles, as this user is already authenticated			
                    UsernamePasswordAuthenticationToken auth =
                	        new UsernamePasswordAuthenticationToken(username,null,authorities);
                	    SecurityContextHolder.getContext().setAuthentication(auth);

                } catch (Exception e) {
                    System.out.println("invalid access...!");
                    throw new RuntimeException("un authorized access to application");
                }
            }
            return chain.filter(exchange);
        });
    }

    public static class Config {

    }
}