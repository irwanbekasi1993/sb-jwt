package sbjwt.payload.request;

public class ResetPasswordRequest {
private String username;
private String email;
private String newPassword;
private Long id;

public ResetPasswordRequest() {
}
public ResetPasswordRequest(String username, String newPassword,String email,Long id) {
    this.username = username;
    this.newPassword = newPassword;
    this.email=email;
    this.id=id;
}



public String getUsername() {
    return username;
}
public void setUsername(String username) {
    this.username = username;
}
public String getNewPassword() {
    return newPassword;
}
public void setNewPassword(String newPassword) {
    this.newPassword = newPassword;
}
public String getEmail() {
    return email;
}
public void setEmail(String email) {
    this.email = email;
}
public Long getId() {
    return id;
}
public void setId(Long id) {
    this.id = id;
}



}
