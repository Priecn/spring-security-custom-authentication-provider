package learn.security;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
import java.util.Collections;
import java.util.List;

@SpringBootApplication
public class CustomAuthenticationProviderApplication {

    public static void main(String[] args) {
        SpringApplication.run(CustomAuthenticationProviderApplication.class, args);
    }

}

@Configuration
@EnableWebSecurity
class CustomSecurityConfiguration extends WebSecurityConfigurerAdapter {

    private final CustomAuthenticationProvider authenticationProvider;

    CustomSecurityConfiguration(CustomAuthenticationProvider authenticationProvider) {
        this.authenticationProvider = authenticationProvider;
    }


    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.httpBasic();
        http.authorizeRequests().anyRequest().authenticated();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(this.authenticationProvider);
    }
}

@RestController
class GreetingRestController {

    @GetMapping("/greeting")
    public String greet(Principal principal) {
        return "hello "+ principal.getName();
    }
}

@Component
class CustomAuthenticationProvider implements AuthenticationProvider {

    private final List<SimpleGrantedAuthority> authorities = Collections.singletonList(new SimpleGrantedAuthority("USER"));

    //call any service to validate
    private boolean isValid(String user, String pw) {
        return user.equals("jlong") && pw.equals("password");
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName();
        String password = authentication.getCredentials().toString();

        if(isValid(username, password))
            return new UsernamePasswordAuthenticationToken(username, password, this.authorities);
        throw new BadCredentialsException("couldn't authenticate using "+ username+ " !");
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}