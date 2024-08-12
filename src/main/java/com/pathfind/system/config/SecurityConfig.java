/*
 * 클래스 기능 : Spring security config class
 * 최근 수정 일자 : 2024.08.08(목)
 */
package com.pathfind.system.config;

import com.pathfind.system.config.filter.JwtAuthenticationFilter;
import com.pathfind.system.config.filter.JwtAuthorizationFilter;
import com.pathfind.system.config.filter.JwtExceptionFilter;
import com.pathfind.system.handler.CustomAuthenticationFailureHandler;
import com.pathfind.system.handler.CustomAuthenticationSuccessHandler;
import com.pathfind.system.handler.CustomLogoutSuccessHandler;
import com.pathfind.system.repository.MemberRepository;
import com.pathfind.system.service.CookieServiceImpl;
import com.pathfind.system.service.JwtServiceImpl;
import com.pathfind.system.service.PrincipalOAuth2UserServiceImpl;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.web.filter.CorsFilter;

@Configuration
@EnableWebSecurity // 스프링 시큐리티 필터(SecurityConfig class)가 스프링 필터 체인에 등록이 된다.
@EnableMethodSecurity(securedEnabled = true) // secured 애노테이션 활성화
@RequiredArgsConstructor
public class SecurityConfig {

    String ACCESS_HEADER_STRING = "Authorization";
    String REFRESH_HEADER_STRING = "Authorization-refresh";

    private final CorsFilter corsFilter;

    private final MemberRepository memberRepository;

    private final JwtServiceImpl jwtService;

    private final CookieServiceImpl cookieService;

    private final PrincipalOAuth2UserServiceImpl principalOAuth2UserService;

    private final CustomAuthenticationSuccessHandler customAuthenticationSuccessHandler;

    private final CustomAuthenticationFailureHandler customAuthenticationFailureHandler;

    private final CustomLogoutSuccessHandler customLogoutSuccessHandler;

    private final JwtExceptionFilter jwtExceptionFilter;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, AuthenticationConfiguration authenticationConfiguration) throws Exception {
        http
                .csrf(CsrfConfigurer::disable); //개발 단계에서는 주석해제, 배포에서는 주석처리

        http
                .authorizeHttpRequests(authorize -> authorize // 인증이 필요한 주소를 등록한다.
                        .anyRequest().permitAll()
                );

        http
                .addFilter(corsFilter);

        http
                .formLogin(formLogin -> formLogin.disable());

        http
                .httpBasic(basic -> basic.disable());

        http
                .oauth2Login(formLogin -> formLogin
                        .userInfoEndpoint(userInfoEndpointConfig -> userInfoEndpointConfig.userService(principalOAuth2UserService))
                        .successHandler(customAuthenticationSuccessHandler) // 커스텀 로그인 성공 핸들러 설정
                        .failureHandler(customAuthenticationFailureHandler) // 커스텀 로그인 실패 핸들러 설정
                );

        http
                .logout(formLogout -> formLogout
                        .logoutUrl("/members/logout")
                        .deleteCookies(ACCESS_HEADER_STRING, REFRESH_HEADER_STRING)
                        .clearAuthentication(true)
                        .logoutSuccessHandler(customLogoutSuccessHandler) // 커스텀 로그아웃 성공 핸들러 설정
                );

        AuthenticationManager authenticationManager = authenticationConfiguration.getAuthenticationManager();

        JwtAuthenticationFilter jwtAuthenticationFilter = new JwtAuthenticationFilter(authenticationManager);
        jwtAuthenticationFilter.setFilterProcessesUrl("/members/login");
        jwtAuthenticationFilter.setUsernameParameter("userId");
        jwtAuthenticationFilter.setAuthenticationSuccessHandler(customAuthenticationSuccessHandler); // 커스텀 로그인 성공 핸들러 설정
        jwtAuthenticationFilter.setAuthenticationFailureHandler(customAuthenticationFailureHandler); // 커스텀 로그인 실패 핸들러 설정

        http
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);


        JwtAuthorizationFilter jwtAuthorizationFilter = new JwtAuthorizationFilter(authenticationManager, memberRepository, jwtService, cookieService);

        http
                .addFilterBefore(jwtAuthorizationFilter, BasicAuthenticationFilter.class);

        http
                .addFilterBefore(jwtExceptionFilter, JwtAuthorizationFilter.class);
        /*http
                .sessionManagement((auth) -> auth
                        .maximumSessions(1) //동일한 아이디로 동시에 허용되는 세션의 최대 개수
                        .maxSessionsPreventsLogin(false)); //최대 세션 개수를 초과할 경우, 이전에 로그인한 세션이 로그아웃되고 새로운 세션이 활성화

        http
                .sessionManagement((auth) -> auth //세션 고정 공격을 방지화
                        .sessionFixation().changeSessionId()); //사용자가 로그인할 때 기존 세션 ID를 새로운 세션 ID로 변경*/

        http
                .sessionManagement(sessionManagement -> sessionManagement
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                );

        return http.build();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }
}
