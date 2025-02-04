package com.springboot.member;

import com.springboot.auth.utils.HelloAuthorityUtils;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@Transactional
public class DBMemberService implements MemberService {
    private final MemberRepository memberRepository;
    private final PasswordEncoder passwordEncoder;
//    회원 갇입시, User의 권한정보(Role)를 데이터베이스에 저장
    private final HelloAuthorityUtils authorityUtils;
// 생성자를 통해 MemebrRepository와 PasswordEncoder 객체를 DI 받는다.
    public DBMemberService(MemberRepository memberRepository, PasswordEncoder passwordEncoder, HelloAuthorityUtils authorityUtils) {
        this.memberRepository = memberRepository;
        this.passwordEncoder = passwordEncoder;
        this.authorityUtils = authorityUtils;
    }

    @Override
    public Member createMember(Member member) {
//        passwordEncoder 를 이용해 패스워드를 암호화 한다.
        String encryptedPassword = passwordEncoder.encode(member.getPassword());
//        패스워드 같은 민감한 정보는 반드시 암호화 되어 저장되야 한다. - 패스워드는 암호화된 상태에서 복호화할 이유가 없어 단방향 암호화 방식으로 암호화 되야 한다.
//        암호화된 비밀번호를 password 필드에 다시 할당한다.
        member.setPassword(encryptedPassword);

        //    Role을 DB에 저장
        List<String> roles = authorityUtils.createRoles(member.getEmail());
        member.setRoles(roles);

        Member savedMember = memberRepository.save(member);

        return savedMember;
    }

}
