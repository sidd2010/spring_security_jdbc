package com.example.spring_security_jdbc;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import javax.sql.DataSource;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {
    @Autowired
    DataSource dataSource;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        // Set your configuration on the auth object
       auth.jdbcAuthentication()
               .dataSource(dataSource)
               //following commands not needed if your schema is same as the default schema , needed if tablenames are other than 'users' and 'authorities
               .usersByUsernameQuery("select username, password, enabled" //change according to your schema in schema.sql file
                       +"from users"
                       +"where username = ?")
               .authoritiesByUsernameQuery("select username, authority"
                       +"from authorities"
                       +"where username =?")
         /*      .withDefaultSchema()  // For Default Schema without an existing database
               .withUser(
                       User.withUsername("user")
                               .password("password")
                               .roles("USER")
               )
               .withUser(User.withUsername("admin")
                       .password("password")
                       .roles("ADMIN")
               )*/;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers("/admin").hasRole("ADMIN")
                .antMatchers("/user").hasAnyRole("ADMIN", "USER")
                .antMatchers("/").permitAll()
                .and().formLogin();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {

        return NoOpPasswordEncoder.getInstance();
    }
}


