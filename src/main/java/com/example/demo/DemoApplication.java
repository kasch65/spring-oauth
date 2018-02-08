package com.example.demo;

import java.security.Principal;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.Filter;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.oauth2.resource.ResourceServerProperties;
import org.springframework.boot.autoconfigure.security.oauth2.resource.UserInfoTokenServices;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.filter.OAuth2ClientAuthenticationProcessingFilter;
import org.springframework.security.oauth2.client.filter.OAuth2ClientContextFilter;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.filter.CompositeFilter;

@SpringBootApplication
@EnableOAuth2Client
@RestController
public class DemoApplication extends WebSecurityConfigurerAdapter
{
  @Autowired
  OAuth2ClientContext oauth2ClientContext;

  @Override
  protected void configure(final HttpSecurity http) throws Exception
  {
    http.antMatcher("/**").authorizeRequests().antMatchers("/", "/login**", "/webjars/**").permitAll().anyRequest().authenticated().and()
        .logout().logoutSuccessUrl("/").permitAll().and().csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()).and()
        .addFilterBefore(ssoFilter(), BasicAuthenticationFilter.class);
  }

  @RequestMapping("/user")
  public Principal user(final Principal principal)
  {
    return principal;
  }

  @Bean
  @ConfigurationProperties("facebook.client")
  public AuthorizationCodeResourceDetails facebook()
  {
    return new AuthorizationCodeResourceDetails();
  }

  @Bean
  @ConfigurationProperties("facebook.resource")
  public ResourceServerProperties facebookResource()
  {
    return new ResourceServerProperties();
  }

  @Bean
  @ConfigurationProperties("github.client")
  public AuthorizationCodeResourceDetails github()
  {
    return new AuthorizationCodeResourceDetails();
  }

  @Bean
  @ConfigurationProperties("github.resource")
  public ResourceServerProperties githubResource()
  {
    return new ResourceServerProperties();
  }

  @Bean
  public FilterRegistrationBean oauth2ClientFilterRegistration(final OAuth2ClientContextFilter filter)
  {
    final FilterRegistrationBean registration = new FilterRegistrationBean();
    registration.setFilter(filter);
    registration.setOrder(-100);
    return registration;
  }

  public static void main(final String[] args)
  {
    SpringApplication.run(DemoApplication.class, args);
  }

  private Filter ssoFilter()
  {
    final CompositeFilter filter = new CompositeFilter();
    final List<Filter> filters = new ArrayList<>();

    final OAuth2ClientAuthenticationProcessingFilter facebookFilter = new OAuth2ClientAuthenticationProcessingFilter("/login/facebook");
    final OAuth2RestTemplate facebookTemplate = new OAuth2RestTemplate(facebook(), oauth2ClientContext);
    facebookFilter.setRestTemplate(facebookTemplate);
    UserInfoTokenServices tokenServices = new UserInfoTokenServices(facebookResource().getUserInfoUri(), facebook().getClientId());
    tokenServices.setRestTemplate(facebookTemplate);
    facebookFilter.setTokenServices(tokenServices);
    filters.add(facebookFilter);

    final OAuth2ClientAuthenticationProcessingFilter githubFilter = new OAuth2ClientAuthenticationProcessingFilter("/login/github");
    final OAuth2RestTemplate githubTemplate = new OAuth2RestTemplate(github(), oauth2ClientContext);
    githubFilter.setRestTemplate(githubTemplate);
    tokenServices = new UserInfoTokenServices(githubResource().getUserInfoUri(), github().getClientId());
    tokenServices.setRestTemplate(githubTemplate);
    githubFilter.setTokenServices(tokenServices);
    filters.add(githubFilter);

    filter.setFilters(filters);
    return filter;
  }
}
