package com.cydeo.service.impl;

import com.cydeo.entity.User;
import com.cydeo.entity.common.UserPrincipal;
import com.cydeo.repository.UserRepository;
import com.cydeo.service.SecurityService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class SecurityServiceImpl implements SecurityService {

    private final UserRepository userRepository;

    public SecurityServiceImpl(UserRepository userRepository) throws UsernameNotFoundException {
        this.userRepository = userRepository;
    }

    public UserDetails loadUserByUsername(String username) {

        User user = userRepository.findByUserNameAndIsDeleted(username, false);

        if (user == null){
            throw new UsernameNotFoundException(username);
        }
        return new UserPrincipal(user);
    }
    //hey get the user from DB, and convert to user spring understands by using user principal
}
