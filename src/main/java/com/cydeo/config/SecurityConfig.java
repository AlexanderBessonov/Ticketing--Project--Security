package com.cydeo.config;


import com.cydeo.service.SecurityService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
public class SecurityConfig {

    private final SecurityService securityService;
    private final AuthSuccessHander authSuccessHander;

    public SecurityConfig(SecurityService securityService, AuthSuccessHander authSuccessHander) {
        this.securityService = securityService;
        this.authSuccessHander = authSuccessHander;
    }

//    @Bean
//    public UserDetailsService userDetailsService(PasswordEncoder encoder){
//
//       // UserDetails user1 = UserDetails new User();
//
//        List<UserDetails> userList = new ArrayList<>();
//
//        userList.add(
//                new User("mike",encoder.encode("password"), Arrays.asList(new SimpleGrantedAuthority("ROLE ADMIN")))
//        );
//
//        userList.add(
//                new User("ozzy",encoder.encode("password"), Arrays.asList(new SimpleGrantedAuthority("ROLE MANAGER")))
//        );
//        return new InMemoryUserDetailsManager(userList);
//    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        return http
                .authorizeRequests()
//                .antMatchers("/user/**").hasRole("ADMIN")
                .antMatchers("/user/**").hasAuthority("Admin")
                .antMatchers("/project/**").hasAuthority("Manager")
                .antMatchers("/task/employee/**").hasAuthority("Employee")
                .antMatchers("/task/**").hasAuthority("Manager")
//                .antMatchers("/task/**").hasAnyRole("EMPLOYEE","ADMIN")
//                .antMatchers("/task/**").hasAuthority("ROLE_EMPLOYEE")
                .antMatchers(
                        "/",
                        "/login",
                        "/fragments/**",
                        "/assets/**",
                        "/images/**"
                ).permitAll()
                .anyRequest().authenticated()
                .and()
//                .httpBasic()

                .formLogin()
                  .loginPage("/login")
            //      .defaultSuccessUrl("/welcome")
                .successHandler(authSuccessHander)
                  .failureUrl("/login?error=true")
                  .permitAll()
                .and()
                .logout()
                  .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
                  .logoutSuccessUrl("/login")
                .and()
                .rememberMe()
                   .tokenValiditySeconds(120)
                   .key("cydeo")
                   .userDetailsService(securityService)
                .and()
                .build();
    }


}