package com.pmc.market.config;

import com.pmc.market.entity.Role;
import com.pmc.market.oauth2.*;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.BeanIds;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@RequiredArgsConstructor
@Configuration
@EnableWebSecurity // Spring security  활설화
@EnableGlobalMethodSecurity( // Security Method  활성화
        securedEnabled = true, // 인가 처리 옵션
        jsr250Enabled = true,
        prePostEnabled = true // @Pre,PostAuthorize 처리 옵션
)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final CustomUserDetailsService customUserDetailsService;

    private final CustomOAuth2UserService customOAuth2UserService;

    private final OAuth2AuthenticationSuccessHandler oAuth2AuthenticationSuccessHandler;

    private final OAuth2AuthenticationFailureHandler oAuth2AuthenticationFailureHandler;

    private final HttpCookieOAuth2AuthorizationRequestRepository httpCookieOAuth2AuthorizationRequestRepository;

    @Bean
    public TokenAuthenticationFilter tokenAuthenticationFilter() {
        return new TokenAuthenticationFilter();
    }

    /*
        JWT를 사용하기 때문에 Sesseion에 저장할 필요가 없어져
        Authorization Request 를 Base64 encoded cookie에 저장
    */
    @Bean
    public HttpCookieOAuth2AuthorizationRequestRepository cookieAuthorizationRequestRepository() {
        return new HttpCookieOAuth2AuthorizationRequestRepository();
    }

    // Authorization 에 사용할 userDetailService 와 Password Encoder 정의
    @Override
    public void configure(AuthenticationManagerBuilder authenticationManagerBuilder) throws Exception {
        authenticationManagerBuilder
                .userDetailsService(customUserDetailsService)
                .passwordEncoder(passwordEncoder());
    }

    // SecurityConfig 에서 사용할 password encoder 를 BCryptPasswordEncoder 로 정의
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // AuthenticationManager 를 외부에서 사용하기 위해 AuthenticationManager Bean을 통해
    // @Autowired 가 아닌 @Bean 설정으로 Spring Security 밖으로 Authentication 추출
    @Bean(BeanIds.AUTHENTICATION_MANAGER)
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                // CORS 허용
                .cors()
                .and()
                // 토큰을 사용하기 위해 sessionCreationPolicy 를 STATELESS 로 설정 (Session 비 활성화)
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                // CSRF 비활성화
                .csrf().disable()
                // 로그인폼 비활성화
                .formLogin().disable()
                // 기본 로그인 창 비활성화
                .httpBasic().disable()
                .authorizeRequests()
                .antMatchers("/").permitAll()
                .antMatchers("/api/**").hasAnyRole(Role.GUEST.name(), Role.BUYER.name())
                .antMatchers("/auth/**", "/oauth2/**").permitAll()
                .anyRequest().authenticated()
                .and()
                .oauth2Login().authorizationEndpoint()
                // 클라이언트 처음 로그인 시도 URI
                .baseUri("/oauth2/authorize")
                .authorizationRequestRepository(cookieAuthorizationRequestRepository())
                .and()
//                .redirectionEndpoint()
//                .baseUri("/oauth2/callback/*")
//                .and()
                .userInfoEndpoint()
                .userService(customOAuth2UserService)
                .and()
                .successHandler(oAuth2AuthenticationSuccessHandler)
                .failureHandler(oAuth2AuthenticationFailureHandler);

        // UsernamePasswordAuthenticationFilter 앞에 custom 필터 추가
        http.addFilterBefore(tokenAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);
    }
}