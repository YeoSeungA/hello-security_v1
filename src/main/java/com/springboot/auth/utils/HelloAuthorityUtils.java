package com.springboot.auth.utils;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.stream.Collectors;

//HelloUserDetailsService에서 Role 기반의 User 권한을 생성하기 위해 사용.
@Component
public class HelloAuthorityUtils {
//    yml 파일의 프로퍼티를 가져오는 표현식 미리 정의한 관리자 권한을 갖는 이메일 주소를 불러온다.
    @Value("${mail.address.admin}")
    private String adminMailAddress;
////AuthorityUtils 클래스를 이용해 관리자용 권한 목록을 List<GrantedAuthority> 객체로 미리 생성
//    private final List<GrantedAuthority> ADMIN_ROLES = AuthorityUtils.createAuthorityList("ROLE_ADMIN", "ROLE_USER");
//    //AuthorityUtils 클래스를 이용해 일반사용 권한 목록을 List<GrantedAuthority> 객체로 미리 생성
//    private final List<GrantedAuthority> USER_ROLES = AuthorityUtils.createAuthorityList("ROLE_USER");

    private final List<String> ADMIN_ROLES_STRING = List.of("ADMIN", "USER");
    private final List<String> USER_ROLES_STRING = List.of("USER");
//// 메모리 상의 Role을 기반으로 권한 정보 생성.
//    public List<GrantedAuthority> createAuthorities (String email) {
////        파라미터로 전달받은 이메일 주소가 yml에서 가져온 관리자용 이메일 주소와 동일하면 관리자용 권한을 리턴한다.
//        if(email.equals(adminMailAddress)) {
//            return ADMIN_ROLES;
//        } else {
//            return USER_ROLES;
//        }
//    }
//    DB에 저장된 Role을 기반으로 권한 정보 생성
//    단순히 데이터베이스에서 가지고 온 Role 목록(List<String> roles)을 그대로 이용해 권한 목록(authorities)을 만든다.
    public List<GrantedAuthority> createAuthorities(List<String> roles) {
        List<GrantedAuthority> authorities = roles.stream()
//                SimpleGrantedAuthority 객체를 생성할 때 생성자 파라미터로 넘겨주는 값이 USER, ADMIN이 아닌 ROLE_USER/ ROLE_ADMIN 형태로 넘겨줘야 한다.
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                .collect(Collectors.toList());
        return authorities;
    }

//    DB 저장용
    public List<String> createRoles(String email) {
        if(email.equals(adminMailAddress)) {
            return ADMIN_ROLES_STRING;
        } else {
            return USER_ROLES_STRING;
        }
    }
}
