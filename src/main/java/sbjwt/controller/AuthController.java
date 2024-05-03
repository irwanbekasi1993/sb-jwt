package sbjwt.controller;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.EnableTransactionManagement;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import sbjwt.model.ERole;
import sbjwt.model.RefreshToken;
import sbjwt.model.Role;
import sbjwt.model.User;
import sbjwt.payload.request.ResetPasswordRequest;
import sbjwt.payload.request.LoginRequest;
import sbjwt.payload.request.SignupRequest;
import sbjwt.payload.request.TokenRefreshRequest;
import sbjwt.payload.response.JwtResponse;
import sbjwt.payload.response.MessageResponse;
import sbjwt.payload.response.TokenRefreshResponse;
import sbjwt.repository.RoleRepository;
import sbjwt.repository.UserRepository;
import sbjwt.security.jwt.JwtUtils;
import sbjwt.security.service.RefreshTokenService;
import sbjwt.security.service.UserDetailsImpl;

@CrossOrigin(origins="*", maxAge=3600)
@RestController
@RequestMapping("/sbjwt/api/auth")
public class AuthController {
    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    RoleRepository roleRepository;

    @Autowired
    UserRepository userRepository;

    @Autowired
    PasswordEncoder encoder;

    @Autowired
    JwtUtils jwtUtils;

    @Autowired
    RefreshTokenService refreshTokenService;

    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@RequestBody LoginRequest loginRequest){
        Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));
        
        SecurityContextHolder.getContext().setAuthentication(authentication);

        
        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        String jwt = jwtUtils.generateJwtToken(userDetails);
        List<String> roles = userDetails.getAuthorities().stream().map(item->item.getAuthority()).collect(Collectors.toList());
        
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(userDetails.getId());
        JwtResponse response = new JwtResponse(jwt,refreshToken.getToken(),userDetails.getId(),userDetails.getUsername(),userDetails.getEmail(),roles);
        
        TokenRefreshRequest requestToken = new TokenRefreshRequest();
        requestToken.setRefreshToken(response.getToken());

        refreshTokenService.findByToken(requestToken.getRefreshToken()).map(refreshTokenService::verifyExpiration);
        User getUser = refreshToken.getUser();
        String obtainToken = jwtUtils.generateTokenFromUsername(getUser.getUsername());
        TokenRefreshResponse tokenResponse = new TokenRefreshResponse(obtainToken,requestToken.getRefreshToken(),getUser.getUsername(),getUser.getRoles());
        return ResponseEntity.ok(tokenResponse);
    }

    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@RequestBody SignupRequest signupRequest){
        if(userRepository.existsByUsername(signupRequest.getUsername())){
            return ResponseEntity.badRequest().body(new MessageResponse("username is exists"));
        }
        if(userRepository.existsByEmail(signupRequest.getEmail())){
            return ResponseEntity.badRequest().body(new MessageResponse("email is exists"));
        }
        User user = new User(signupRequest.getUsername(), signupRequest.getEmail(), encoder.encode(signupRequest.getPassword()));
        Set<String> strRoles = signupRequest.getRole();
        Set<Role> roles = new HashSet<>();

        if(strRoles==null){
            Role userRole = roleRepository.findByName(user.getRoles().stream().map(x->x.getName()).toString()).orElseThrow(()-> new RuntimeException("role not found"));
            roles.add(userRole);
        }
        // else{
            // strRoles.forEach(role->{
            //     switch(role){
            //         case "admin": 
            //         Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN.name()).orElseThrow(()-> new RuntimeException("role not found"));
            //         roles.add(adminRole);
            //         break;
            //         case "mod": 
            //         Role modRole = roleRepository.findByName(ERole.ROLE_MODERATOR.name()).orElseThrow(()-> new RuntimeException("role not found"));
            //         roles.add(modRole);
            //         break;
            //         default: 
            //         Role userRole = roleRepository.findByName(ERole.ROLE_USER.name()).orElseThrow(()-> new RuntimeException("role not found"));
            //         roles.add(userRole);
                    
            //     }
            // });
        // }
        for(String strRole: strRoles){
            Role role = roleRepository.findByName(strRole).get();
            roles.add(role);
        }
        user.setRoles(roles);
        userRepository.save(user);
        return ResponseEntity.ok(new MessageResponse("user registered successfully"));
    }


        @PutMapping("/resetPassword")
    public ResponseEntity<?> resetPassword(@RequestBody ResetPasswordRequest resetPassword){
        boolean flag = userRepository.findByUsername(resetPassword.getUsername()).isPresent();
        if(flag){
            userRepository.resetPassword(encoder.encode(resetPassword.getNewPassword()), resetPassword.getUsername(),resetPassword.getEmail(),resetPassword.getId());
        }
        return ResponseEntity.ok(new MessageResponse("Password Change Successfully"));

    }

}
