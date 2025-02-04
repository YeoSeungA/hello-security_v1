package com.springboot.auth.utils;

import com.springboot.exception.BusinessLogicException;
import com.springboot.exception.ExceptionCode;
import com.springboot.member.Member;
import com.springboot.member.MemberRepository;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.List;
import java.util.Optional;

//UserDetailsService 란 User 정보를 load 하는 핷미 인터페이스이다.
// load란 인증에 필요한 User 정보를 어딘가에서 가지고 온다는 의미이다.
@Component
//CuystomUserDetailsService를 구현하기 위해서는 UserDetailsService 인터페이스를 구현해야 한다.
public class HelloUserDetailsService implements UserDetailsService {
    private final MemberRepository memberRepository;
    private final HelloAuthorityUtils authorityUtils;
//데이터베이스에서 User를 조회, 조회한 User의 권한(Role)정보를 생성하기 위해 DI 받는다.
    public HelloUserDetailsService(MemberRepository memberRepository, HelloAuthorityUtils authorityUtils) {
        this.memberRepository = memberRepository;
        this.authorityUtils = authorityUtils;
    }
//    UserDetailsService인터페이스를 implements 하는 구현 클래스는 loadUserByUSername이라는 추상 메서드를 구현해야 한다.
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Optional<Member> optionalMember = memberRepository.findByEmail(username);
        Member findMember = optionalMember.orElseThrow(() -> new BusinessLogicException(ExceptionCode.MEMBER_NOT_FOUND));
//        너무 많은 일을 실행하고 있기 때문에 해야할 일을 나눠주자.
//      Role 기반의 권한정보(Grant) 컬렉션을 생성한다.
//        Collection<? extends GrantedAuthority> authorities = authorityUtils.createAuthorities(findMember.getEmail());
//      데이터베이스에서 조회한 인증정보와, 생성한 권한 정보를 Security에서는 모르기 때문에 Security에 정보들을 제공해줘야 한다.
//        UserDetails 인터페이스의 구현체인 User 클래스의 객체를 통해 제공.
//        return new User(findMember.getEmail(), findMember.getPassword(), authorities);
        return new HelloUserDetails(findMember);
    }
// UserDetails 클래스는 UserDetails 인터페이스를 구현하고 있고 또, Member 엔티티 클래스를 상속받는다.
//    데이터 베이스에서 조회한 회원 정보를 Security의 User 정보로 변환하는 과정과 User의 권한 정보를 생성하는 과정을 캡슐화 할 수 있다.
    private final class HelloUserDetails extends Member implements UserDetails {

        public HelloUserDetails(Member member) {
            setMemberId(member.getMemberId());
            setFullName(member.getFullName());
            setEmail(member.getEmail());
            setPassword(member.getPassword());
//            데이터 베이스에서 조회한 List<String> roles를 전달한다.
            setRoles(member.getRoles());
        }

        @Override
        public Collection<? extends GrantedAuthority> getAuthorities() {
//            DB에 저당된 Role 정보로 User 권한 목록 생성(List<GrantedAuthority>)
            return authorityUtils.createAuthorities(this.getRoles());
        }
//      Security에서 인식할 수 있는 username을 Member 클래스의 email 주소로 채우고 있다.
        @Override
        public String getUsername() {
            return getEmail();
        }

        @Override
        public boolean isAccountNonExpired() {
            return true;
        }

        @Override
        public boolean isAccountNonLocked() {
            return true;
        }

        @Override
        public boolean isCredentialsNonExpired() {
            return true;
        }

        @Override
        public boolean isEnabled() {
            return true;
        }
    }

//     ** 데이터베이스에서 User의 인증 정보만 Security에 넘겨주고, 인증 처리는 Security가 대신 해준다.
//    ** UserDetails는 UserDetailsService에 의해 로드되어 인증을 위해 사용되는 User 정보를 표현하는 인터페이스이다.
//    ** UserDetails 인터페이스의 구현체는 Spring Security에서 보안 정보 제공을 목적으로 직접 사용은 X, Authentication 객체로 캡슐화되어 제공된다.

}
