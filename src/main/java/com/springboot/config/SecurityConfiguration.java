package com.springboot.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.stereotype.Component;

//Spring Security Configuration 을 적용하면 원하는 인증 방식과 웹 페이지에 대한 접근 권한을 설정할 수 있다.
@Configuration
public class SecurityConfiguration {
//    HttpSecurity를 파라미터로 갖고, SecurityFilterChain을리턴해 Http 보안 설정을 구성할 수 있다.
//    HttpSecurity는 HTTP 요청에 대한 보안 설정을 구성하기 위한 핵심 클래스이다.
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
//                frameOptions()는 HTML 태그 중 <frame>, <iframe>, <object> 태그에서 페이지를 렌더링 할지의 여부를 결정하는 기능을 한다.
//                Security는 Clickjacking 공격을 막기위해 frameOption 기능이 활성화 되어 있따. 디폴트는 DENY로 태그를 이용한 렌더링 X
//                .frameOptions().sameOrigin()을 호출해 동일 호출로부터 들어오는 request만 페이지 렌더링을 허용
                .headers().frameOptions().sameOrigin()
                .and()
//                CSRF(Cross-Site Request Forgery) 공격에 대해 Spring Security 에 대한 설정을 비활성화 한다. - 로컬환경이기에
//                기본적으로는 아무 설정을 하지 않으면 csrf() 공격을 방지하기 위해 클라이언트로부터 CSRF Token을 수신 후 검증한다.
                .csrf().disable()
//                기본적인 인증방법을 폼 로그인 방식으로 지정한다.
                .formLogin()
//                templates 패키지의 커스텀 login 페이지를 이용한다.
//                AuthsController의 loginForm() 핸들러 메서드에 요청을 전송하는 URL
                .loginPage("/auths/login-form")
//                인증 요청을 수행할 요청 URL을 지정한다.
                .loginProcessingUrl("/process_login")
//                로그인 인증에 실패할 경우 어떤 화면으로 리다이렉트 할 것인가 지정한다.
                .failureUrl("/auths/login-form?error")
//                Spring Security 보안 설정을 메서드 체인 형태로 구성할 수 있다.
                .and()
//                로그 아웃 추가 설정 LogoutConfigurer를 리턴
                .logout()
//                사용자가 로그아웃을 수행하기 위한 request URL을 지정한다.
//                header.html의 로그아웃 메뉴에 지정한 href="/logout"과 동일하다.
                .logoutUrl("/logout")
//                로그아웃을 성공적으로 수행 후 리다이랙트할 URL 지정, 메인화면으로 지정
                .logoutSuccessUrl("/")
                .and()
//                권한 없는 사용자가 특정 request URI에 접근할 경우 403(Forbidden)에러를 처리하기 위한 페이지를 설정했다.
//                exceptionHandling()는 Exception을 처리하는 기능, 리턴하는 ExceptionHandlingConfigurer 객체를 통해 구체적인 Exception 처리가 가능하다.
                .exceptionHandling().accessDeniedPage("/auths/access-denied")
                .and()
//                클라이언트의 요청이 들어오면 접근 권한을 확인하겠다고 정의한다.
//                람다표현식을 통해 request URI에 대한 접근 권한을 부여할 수 있다.
//                더 구체적인 URL 경로부터 접근 권한을 부여한 다음 덜 구체적인 URL 경로에 접근 권한을 부여해야 한다.
                .authorizeHttpRequests(authorize -> authorize
//                        antMatchers는 ant라는 빌드 툴에서 사용되는 Path Pattrern을 이용해 매치되는 URL을 표현
//                        **은 orders의 모든 하위 URL을 포함한다.
                        .antMatchers("/orders/**").hasRole("ADMIN")
                        .antMatchers("/members/my-page").hasRole("USER")
                        .antMatchers("/**").permitAll()
                );
        return http.build();

    }
//    PasswordEncoder Bean 등록으로, PasswordEncoder는 패스워드 암호화 기능을 제공하는 컴포넌트이다.
    @Bean
    public PasswordEncoder passwordEncoder() {
//        PasswordEncoder는 다양한 암호화 방식이 있으며 디폴트 암호화 알고리즘은 bcrypt(단방향 해시 알고리즘) 이다.
//        PasswordEncoderFactories.createDelegatingPasswordEncoder()를 통해 DelegatingPasswordEncoder를 먼저 생성하고
//        이 DelegatingPasswordEncoder가 실질적으로 PasswordEncoder 구현 객체를 생성해준다.
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }
}
