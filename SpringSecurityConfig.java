package com.sathyatech.app.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

// make bean of passwordencoder in configuration file.

@Bean
	public BCryptPasswordEncoder passwordEncoder() {
		BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder();
		return bCryptPasswordEncoder;
	}

--------------------------------------------------------------------

// main configuration class

	@Configuration
@EnableWebSecurity 
public class WebSecurityConfig extends WebSecurityConfigurerAdapter{
	@Autowired
	private BCryptPasswordEncoder bCryptPasswordEncoder;
	@Autowired
	private UserDetailsService userDetailsService; 
	
	@Autowired
	public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception{
		auth.userDetailsService(userDetailsService).passwordEncoder(bCryptPasswordEncoder);
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.authorizeRequests()
		.antMatchers("/").permitAll()
		.antMatchers("/login","/register","/saveUser").permitAll()
		.antMatchers("/uom**").hasAuthority("USER")
		
		.anyRequest().authenticated()
		
		.and().csrf().disable()
		
		.formLogin()
		.loginPage("/login").failureUrl("/login?error=true")
		.defaultSuccessUrl("/uom/register")
		.usernameParameter("username")
		.passwordParameter("password")
		
		.and()
		.logout()
		.logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
		.logoutSuccessUrl("/login?logout=true")
		
		.and()
		.exceptionHandling()
		.accessDeniedPage("/AccessDenied");
	}
}


// UserDetailsService implementation class


package com.sathyatech.app.service.impl;

import java.util.HashSet;
import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.sathyatech.app.model.Role;
import com.sathyatech.app.model.User;
import com.sathyatech.app.repo.UserRepository;

@Service
public class UserDetailsServiceImpl implements UserDetailsService{
    @Autowired
    private UserRepository userRepository;

    @Override
    @Transactional(readOnly = true)
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUserEmail(username);

        Set<GrantedAuthority> grantedAuthorities = new HashSet<>();
        for (Role role : user.getRoles()){
            grantedAuthorities.add(new SimpleGrantedAuthority(role.getRoleName()));
        }

        return new org.springframework.security.core.userdetails.User(user.getUserEmail(), user.getPassword(), grantedAuthorities);
    }
}



// to save user from login registration and while fetching his credentials.

package com.sathyatech.app.service.impl;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import com.sathyatech.app.model.User;
import com.sathyatech.app.repo.UserRepository;
import com.sathyatech.app.service.IUserService;


@Service("userService")
public class UserServiceImpl implements IUserService{

	@Autowired
	private UserRepository userRepository;
	
	
    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;
	
	@Override
	public User findUserByEmail(String email) {
		return userRepository.findByUserEmail(email);
	}

	@Override
	public void saveUser(User user) {
		user.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
        user.setActive(1);
		userRepository.save(user);
	}

}
