package com.klimber.opaquetoken.resource;

import java.security.Principal;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloResource {

    @GetMapping("/hello")
    public ResponseEntity<String> hello() {
        return ResponseEntity.ok("Hello, World!");
    }

    @GetMapping("/secure/hello")
    public ResponseEntity<String> helloSecure(Principal principal) {
        return ResponseEntity.ok("Hello, Secure " + principal.getName() + "!");
    }
}
