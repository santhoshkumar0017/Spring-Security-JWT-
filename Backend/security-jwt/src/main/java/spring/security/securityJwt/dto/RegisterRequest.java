package spring.security.securityJwt.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.Set;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor

public class RegisterRequest {

    private String userName;
    private String password;
    private Set<String> roles; // A set of role name , to be passed in the request
}
