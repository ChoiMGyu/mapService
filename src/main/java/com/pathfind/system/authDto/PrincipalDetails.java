/*
 * 클래스 기능 : 스프링 시큐리티에서 일반 로그인, OAuth 로그인 둘 다 하나의 클래스로 구현하여 사용할 수 있게 한다.
 * 최근 수정 일자 : 2024.05.19(일)
 */
package com.pathfind.system.authDto;

import com.pathfind.system.domain.Member;
import lombok.Data;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;


import java.util.Collection;
import java.util.Map;

@Data
public class PrincipalDetails implements UserDetails, OAuth2User {

    private Member member;

    private Map<String, Object> attributes;

    // 일반 로그인 시 사용하는 생성자
    public PrincipalDetails(Member member) {
        this.member = member;
    }

    // OAuth 로그인 시 사용하는 생성자
    public PrincipalDetails(Member member, Map<String, Object> attributes) {
        this.member = member;
        this.attributes = attributes;
    }

    @Override
    public String getName() {
        return member.getNickname();
    }

    @Override
    public Map<String, Object> getAttributes() {
        return attributes;
    }

    // 해당 Member의 권한을 리턴하는 함수이다.
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        // Member의 권한이 필요한 경우 Member 엔티티에 String Role 데이터 멤버를 추가해서 사용한다.
        /*Collection<GrantedAuthority> collect = new ArrayList<>();
        collect.add(new GrantedAuthority() {
            @Override
            public String getAuthority() {
                return member.getRole();
            }
        });
        return collect;*/
        return null;
    }

    @Override
    public String getPassword() {
        return member.getPassword();
    }

    @Override
    public String getUsername() {
        return member.getNickname();
    }

    /**
     * 계정이 만료되었는지 여부를 boolean 타입으로 반환한다.
     */
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    /**
     * 계정이 잠겼는지 여부를 boolean 타입으로 반환한다.
     */
    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    /**
     * 동일한 비밀번호를 사용할 수 있는 기간이 지났는지 여부를 boolean 타입으로 반환한다.
     */
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    /**
     * 계정 사용이 가능한지 여부를 boolean 타입으로 반환하는 함수이다.
     * 휴면 계정 전환 등을 구현하고 싶다면 이 함수를 사용하면 된다.
     */
    @Override
    public boolean isEnabled() {
        return true;
    }
}
