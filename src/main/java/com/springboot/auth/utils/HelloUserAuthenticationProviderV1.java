package com.springboot.auth.utils;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.Objects;
import java.util.Optional;

// Custom UserDetailsService를 사용해 로그인 인증을 처리하는 방식은 Security가 내부적으로 인증을 대신 처리해주는 방식이다.
//Custom AuthenticationProvider를 이용해 우리가 직접 로그인 인증을 처리하는 방법이다.
//핵심 컴포넌트인 AuthenticationProvider를 이해하고 보안 요구 사항에 부합하는 적절한 인증방식을 직접 구현할 때 필요하다.
@Component
//AuthenticationProvider의 인터페이스의 구 현 클래스로 정의한다.
//AuthenticationProvider 얘가 실제 인증 인증이 긑난 AuthenticationProvider를 ed
public class HelloUserAuthenticationProviderV1 implements AuthenticationProvider {
    private final HelloUserDetailsService userDetailsService;
    private final PasswordEncoder passwordEncoder;

    public HelloUserAuthenticationProviderV1(HelloUserDetailsService userDetailsService, PasswordEncoder passwordEncoder) {
        this.userDetailsService = userDetailsService;
        this.passwordEncoder = passwordEncoder;
    }

// AuthenticationProvider 인터페이스의 구현 클래스는 authenticate(Authentication authentication) 메서드와 supports(Class<?> authentication) 메서드를 구현해야 한다.
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
//        authentication을 캐스팅 해 UsernamePasswordAuthenticationToken을 얻는다.
        UsernamePasswordAuthenticationToken authToken = (UsernamePasswordAuthenticationToken) authentication;
//      UsernamePasswordAuthenticationToken 객체에서 해당 사용자의 Username을 얻은 후 존재하는지 조회한다.
        String username = authToken.getName();
        Optional.ofNullable(username).orElseThrow(()-> new UsernameNotFoundException("Invalid User name or User Password"));
        try{
//      username이 존재한다면 userDetailsService를 이용해 데이터베이스에서 해당 사용자를 조회한다.
            UserDetails userDetails = userDetailsService.loadUserByUsername(username);
            String password = userDetails.getPassword();
//      로그인 정보에 포함된 패스워드(authToken.getCredentials())와 데이터베이스에 저장된 사용자의 패스워드 정보가 일치하는가.
            verifyCredentials(authToken.getCredentials(), password);
//      검증 과정을 통과했다면 로그인 인증에 성공한 사용자이므로, 해당 사용자의 권한을 생성합니다.
            Collection<? extends GrantedAuthority> authorities = userDetails.getAuthorities();
//      인증된 사용자의 인증 정보를 리턴값으로 전달한다.
            return UsernamePasswordAuthenticationToken.authenticated(username, password, authorities);
        } catch (Exception e) {
//            UsernameNotFoundException은 AuthenticationException을 상속하는 하위 Exception이기 때문에 UsernameNotFoundException이 throw 되면
//            리다이렉트 시켜준다.
            throw new UsernameNotFoundException(e.getMessage());
        }

    }
// HelloUserAuthenticationProvider가 Username/Password 방식의 인증을 지원한다는 것을 Security에 알려준다.
    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.equals(authentication);
    }

    private void verifyCredentials(Object credentials, String password) {
        if (!passwordEncoder.matches((String) credentials, password)) {
            throw new BadCredentialsException("Invalid User name or User Password");
        }
    }
//    ** MemberService에서 등록된 회원정보가 없으면, BusinessLogicException을 throw 하는데 이 BusinessLogicException이
//    ** Custom Authentication Provider를 거쳐 그대로 Spring Security 내부 영역으로 throw 되기에 Whitelaber Error Page가 뜬다.
//    ** so, Custom AuthenticationProvider에서 Exception이 발생할 경우, 이 Exception을 catch해 AuthenticaionException으로 rethrow 해준다.
//    ** Custom AuthenticationProvider에서 AuthenticationException이 아닌 Exception이 발생할 경우 곡 AuthenticationException을 rethrow 하도록 구성해야 한다!!!!!
}
