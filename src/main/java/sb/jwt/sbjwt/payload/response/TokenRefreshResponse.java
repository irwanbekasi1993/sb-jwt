package sb.jwt.sbjwt.payload.response;

import java.util.Set;

import sb.jwt.sbjwt.model.Role;
import sb.jwt.sbjwt.model.User;

public class TokenRefreshResponse {
    private String accessToken;
    private String refreshToken;
    private String tokenType="Bearer ";
    private String username;
    private Set<Role> roles;
    public TokenRefreshResponse(String accessToken, String refreshToken, String username, Set<Role> roles) {
        this.refreshToken = refreshToken;
        this.accessToken = accessToken;
        this.username=username;
        this.roles=roles;
    }
    
    

    public String getUsername() {
        return username;
    }



    public void setUsername(String username) {
        this.username = username;
    }




    public Set<Role> getRoles() {
        return roles;
    }



    public void setRoles(Set<Role> roles) {
        this.roles = roles;
    }



    public String getAccessToken() {
        return accessToken;
    }
    public void setAccessToken(String accessToken) {
        this.accessToken = accessToken;
    }
    public String getRefreshToken() {
        return refreshToken;
    }
    public void setRefreshToken(String refreshToken) {
        this.refreshToken = refreshToken;
    }
    public String getTokenType() {
        return tokenType;
    }
    public void setTokenType(String tokenType) {
        this.tokenType = tokenType;
    }


    
}
