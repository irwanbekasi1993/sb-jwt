package sb.jwt.sbjwt.security.jwt;

import java.util.Date;

import org.apache.tomcat.util.codec.binary.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.UnsupportedJwtException;
import sb.jwt.sbjwt.security.service.UserDetailsImpl;

@Component
public class JwtUtils {
    private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);

    @Value("${sbjwt.jwtSecret}")
    private String jwtSecret;

    @Value("${sbjwt.jwtExpirationInMs}")
    private String jwtExpirationInMs;

    public String generateJwtToken(UserDetailsImpl userPrincipal){
        return generateTokenFromUsername(userPrincipal.getUsername());
    }

    public String generateTokenFromUsername(String username){
        return Jwts.builder().setSubject(username)
        .setIssuedAt(new Date())
        .setExpiration(new Date(System.currentTimeMillis()+Long.parseLong(jwtExpirationInMs)))
        .signWith(SignatureAlgorithm.HS512, jwtSecret)
        .compact();
    }

    public String getUserNameFromJwtToken(String token){
        return Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token).getBody().getSubject();
    }

    public boolean validateJwtToken(String authToken){
        boolean flag=false;
        try {
            Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(authToken);
            flag=true;
        } catch (SignatureException e) {
            //TODO: handle exception
            flag=false;
            logger.error("signature problem "+e.getMessage());
        }catch(MalformedJwtException e){
            flag=false;
            logger.error("jwt format problems "+e.getMessage());
        }catch(ExpiredJwtException e){
            flag=false;
            logger.error("jwt is expired "+e.getMessage());
        }catch(UnsupportedJwtException e){
            flag=false;
            logger.error("jwt not supported "+e.getMessage());
        }catch(IllegalArgumentException e){
            flag=false;
            logger.error("others error "+e.getMessage());
        }
        return flag;
    }


}
