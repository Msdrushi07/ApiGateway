
package com.gateway.jwt;

import java.security.Key;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Header;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
public class jwtService {

	public static final String SECRET = "5367566B59703373367639792F423F4528482B4D6251655468576D5A71347437";

	public String generateToken(String userName) {
		Map<String, Object> claims = new HashMap<>();
		claims.put("user data as a payload key", "value");
		claims.put("sub","token provider");
		claims.put("roles",new ArrayList<>(Arrays.asList("user","admin")));
		claims.put("fixed_roles",List.of("admin","user"));
		return createToken(claims, userName);
	}

	private String createToken(Map<String, Object> claims, String userName) {
		Map<String,Object> headers = new HashMap<>();
		headers.put(Header.TYPE,"jwt");
		return Jwts.builder()
				.setHeader(headers)
				.setClaims(claims)
				.setSubject(userName).
				setIssuedAt(new Date(System.currentTimeMillis()))
				.setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 30))
				.signWith(getSignKey(), SignatureAlgorithm.HS256).compact();
	}

	public boolean validateToken(final String token) {
		log.info("inside validate token method");
		try {
		Jwts.parserBuilder().setSigningKey(getSignKey()).build().parseClaimsJws(token);
		return true;
		}
		catch(MalformedJwtException ex) {
			return false;
		}
	}

	public String extractUsername(String token) {
		return extractClaim(token, Claims::getSubject);
	}

	public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
		final Claims claims = extractAllClaims(token);
//		String[] res=claims.get("roles",String[].class);
		//	List<String> list=Arrays.asList(res);
		return claimsResolver.apply(claims);
	}

	public Claims extractAllClaims(String token) {
		return Jwts.parserBuilder().setSigningKey(getSignKey()).build().parseClaimsJws(token).getBody();
		// here .parseClaimsJws(token) will validate the signature,expiry etc then only return all the claims
	}

	private Boolean isTokenExpired(String token) {
		return extractExpiration(token).before(new Date());
	}

	public Date extractExpiration(String token) {
		return extractClaim(token, Claims::getExpiration);
	}

	private Key getSignKey() {
		byte[] keyBytes = Decoders.BASE64.decode(SECRET);
		return Keys.hmacShaKeyFor(keyBytes);
	}
}
