package spring.security.securityJwt.security;

import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.hibernate.dialect.function.StringFunction;
import org.springframework.stereotype.Component;
import spring.security.securityJwt.entity.Role;
import spring.security.securityJwt.entity.User;
import spring.security.securityJwt.repository.UserRepository;

import javax.crypto.SecretKey;
import javax.xml.crypto.Data;
import java.util.Date;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

@Component
public class JwtUtil {

    //Secret key , HS512 Algorithm create random key
    private static final SecretKey secretKey= Keys.secretKeyFor(SignatureAlgorithm.HS512);

    //Expire time
    private final int jwtExpirationMs=86400000;

    private UserRepository userRepository;

    public JwtUtil(UserRepository userRepository){
        this.userRepository=userRepository;
    }

    //Generate token
    public String generateToken(String userName){
        Optional<User> user = userRepository.findByUserName(userName);
        Set<Role> roles = user.get().getRoles();


        return Jwts.builder().setSubject(userName).claim("roles",roles.stream()
                .map(role -> role.getName()).collect(Collectors.joining(",")))
                .setIssuedAt(new Date()).setExpiration(new Date(new Date().getTime()+jwtExpirationMs))
                .signWith(secretKey).compact();

    }
    //Extract Username
    public String extractUsername(String token){
        return Jwts.parserBuilder().setSigningKey(secretKey).build().parseClaimsJws(token).getBody().getSubject();
    }

    //Extract roles
    public Set<String> extractRoles(String tokens){
        String roleString =Jwts.parserBuilder().setSigningKey(secretKey)
                .build().parseClaimsJws(tokens).getBody().get("roles",String.class);

        return Set.of(roleString);
    }

    public boolean isTokenValid(String token){
        try{
            Jwts.parserBuilder().setSigningKey(secretKey).build().parseClaimsJws(token);
            return true;
        }
        catch (JwtException | IllegalArgumentException e){
            return false;
        }
    }

}
