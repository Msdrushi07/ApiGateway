package com.gateway.filter;

import com.gateway.ApiGatewayApplication;

import com.gateway.jwt.jwtService;

import io.jsonwebtoken.Claims;
import lombok.extern.slf4j.Slf4j;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.client.RestTemplate;

@Component
@Slf4j
public class AuthenticationFilter extends AbstractGatewayFilterFactory<AuthenticationFilter.Config> {

	private final ApiGatewayApplication apiGatewayApplication;

	@Autowired
	private RouteValidator validator;

	// @Autowired
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
				log.info("inside filter method");
				// header contains token or not
				if (!exchange.getRequest().getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
					throw new RuntimeException("missing authorization header");
				}

				String authHeader = exchange.getRequest().getHeaders().get(HttpHeaders.AUTHORIZATION).get(0);
				if (authHeader != null && authHeader.startsWith("Bearer ")) {
					authHeader = authHeader.substring(7);
				}
				try {
					log.info(authHeader);
//                    //REST call to AUTH service
//                    template.getForObject("http://IDENTITY-SERVICE//validate?token" + authHeader, String.class);
					Claims claims = jwtUtil.extractAllClaims(authHeader); // here if we have claims after
																			// .parseClaimsJws(token) then token is
																		// valid or trusted
					String username = claims.getSubject();
					log.info(username);
					List<String> listOfRoles = claims.get("roles", List.class);
					List<GrantedAuthority> authorities = listOfRoles.stream()
							.map(role -> new SimpleGrantedAuthority(role)).collect(Collectors.toList());
					// buliding an authentication object by providing username,roles, as this user
					// is already authenticated
					// to validate role based authontication at microservice level add
					// @PreAuthorize("hasRole('EMPLOYEE')") or @PreAuthorize("hasRole('ADMIN')")
					UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(username, null,
							authorities);
					SecurityContextHolder.getContext().setAuthentication(auth);
					// this SecurityContextHolder is applicable only for the gateway and will not routed to perticular microservice
					// once request is routed we don't have anything in SecurityContextHolder (role,username etc)
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