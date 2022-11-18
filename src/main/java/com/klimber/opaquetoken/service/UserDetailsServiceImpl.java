package com.klimber.opaquetoken.service;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.stereotype.Service;

/**
 * Class for managing accounts that implements UserDetailsManager.
 *
 * <p>Here I'm using the InMemoryUserDetailsManager implementation as example and adding some test users, but it might
 * as well be a class that implements UserDetailsManager directly and interacts with a JPA repository of some model that
 * implements UserDetails.</p>
 */
@Service
public class UserDetailsServiceImpl extends InMemoryUserDetailsManager implements UserDetailsManager {

    public UserDetailsServiceImpl() {
        super(User.withUsername("admin").password("{noop}admin").authorities("read").build(),
              User.withUsername("klimber").password("{noop}password").authorities("read").build());
    }
}
