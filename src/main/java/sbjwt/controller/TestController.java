package sbjwt.controller;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import sbjwt.model.ERole;
import sbjwt.model.Role;
import sbjwt.model.User;
import sbjwt.payload.response.MessageResponse;
import sbjwt.payload.response.UserResponse;
import sbjwt.repository.RoleRepository;
import sbjwt.repository.UserRepository;

@CrossOrigin(origins="*", maxAge=3600)
@RestController
@RequestMapping("/sbjwt/api/test")
public class TestController {

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private UserRepository userRepository;

    private static Logger log = LoggerFactory.getLogger(TestController.class);


    @PostMapping("/insertRole")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> insertRole(@RequestBody Role role){
        boolean flag = roleRepository.findByName(role.getName()).isPresent();
        if(!flag){
            Role cekRole = roleRepository.save(role);
            return ResponseEntity.ok(cekRole); 
        }
        return ResponseEntity.ok(new MessageResponse("Role Already Exists")); 
        
    }

    @PutMapping("/updateRole")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> updateRole(@RequestBody Role role,@PathVariable("name") String name){
        boolean flag = roleRepository.findByName(role.getName()).isPresent();
        if(flag){
            Role cekRole = roleRepository.save(role);
            return ResponseEntity.ok(cekRole); 
        }
        return ResponseEntity.ok(new MessageResponse("Role Not Found")); 
     
    }

    @DeleteMapping("/deleteRole")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> deleteRole(@PathVariable("name") String name){
        Role cekRole = roleRepository.findByName(name).get();
        if(cekRole!=null){
            roleRepository.delete(cekRole);
        }
        return ResponseEntity.ok(new MessageResponse("role successfully deleted"));
    }

    @GetMapping("/viewAllUser")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> viewAllUser(){
        List<User> userList = userRepository.findAll();
        return ResponseEntity.ok(userList.stream().map(x->new UserResponse(x.getId(),x.getUsername(),x.getEmail(),x.getRoles())).collect(Collectors.toList()));
    }

    @GetMapping("/all")
    public String allAccess(){
        return "public content";
    }

    @GetMapping("/admin")
    @PreAuthorize("hasRole('ADMIN')")
    public String adminAccess(){
        return "admin board";
    }

    @GetMapping("/user")
    @PreAuthorize("hasRole('USER')")
    public String userAccess(){
        return "user content";
    }

    @GetMapping("/mod")
    @PreAuthorize("hasRole('MODERATOR')")
    public String modAccess(){
        return "mod content";
    }

    @GetMapping("/operational")
    @PreAuthorize("hasRole('OPERATIONAL')")
    public String operationalAccess(){
        return "operational content";
    }

    @GetMapping("/manager")
    @PreAuthorize("hasRole('MANAGER')")
    public String managerAccess(){
        return "manager content";
    }
}
