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

// authenticate user programmatically
// here our model class, AutoUSer must implements UserDetails interface. 

@RequestMapping(value= {"/register"}, method=RequestMethod.POST)
	public String register(@ModelAttribute AutoUser user){
		
		user.setRole("ROLE_USER");
		repo.save(user);
		
		Authentication auth = new UsernamePasswordAuthenticationToken(user, user.getPassword()
				,user.getAuthorities());
		SecurityContextHolder.getContext().setAuthentication(auth);
		
		return "redirect:/";
	}


// logout with jsp and spring security

<%@ taglib uri="http://www.springframework.org/tags" prefix="spring"%>
 <%@ taglib uri="http://www.springframework.org/security/tags" prefix="sec" %>  
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>


<script type="text/javascript">

$(document).ready(function(){
	 
	  $("#logout").click(function(e){
		 e.preventDefault();
		 $("#logout-form").submit();
	  });
});


</script>

	<nav class="navbar navbar-inverse navbar-static-top">
		<div class="container">
			<div class="navbar-header">
				<a href="<spring:url value="/"/>" class="navbar-brand">Kevin's Auto Service Center</a>
			</div>
			<ul class="nav navbar-nav">
				<li><a href="<spring:url value="/services/"/>">Services</a></li>
				<li><a href="<spring:url value="/appointments/"/>">Appointments</a></li>
				<li><a href="<spring:url value="/schedule/"/>">Schedule</a></li>
				
				<sec:authorize access="authenticated" var="authenticated"/>
				<c:choose>
					<c:when test="${authenticated}">
						<li>
							<p class="navbar-text">
								Welcome
								<sec:authentication property="name"  />
								<a id="logout" href="#">Logout</a>
							</p>
							<form id="logout-form" action="<c:url value="/logout"/>" method="post">
								<sec:csrfInput/>
							</form>
						</li>	
					</c:when>
					<c:otherwise>
						<li><a href="<spring:url value="/login/"/>">Sign In</a></li>			
						<li><a href="<spring:url value="/register/"/>">Register</a></li>	
					</c:otherwise>
				</c:choose>
				
				
			</ul>
		</div>
	</nav>
