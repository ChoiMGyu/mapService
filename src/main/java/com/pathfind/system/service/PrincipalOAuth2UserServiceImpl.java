/*
 * 클래스 기능 : OAuth 로그인 시 PrincipalDetails(UserDetails 구현체)를 만들기 위해 사용되는 클래스
 * 최근 수정 일자 : 2024.05.29(수)
 */
package com.pathfind.system.service;

import com.pathfind.system.authDto.PrincipalDetails;
import com.pathfind.system.domain.Check;
import com.pathfind.system.domain.Member;
import com.pathfind.system.provider.GoogleUserInfo;
import com.pathfind.system.provider.NaverUserInfo;
import com.pathfind.system.provider.OAuth2UserInfo;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class PrincipalOAuth2UserServiceImpl extends DefaultOAuth2UserService {

    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    private final MemberService memberService;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        logger.info("Get client registration: {}", userRequest.getClientRegistration());
        logger.info("Get access token: {}", userRequest.getAccessToken());

        OAuth2User oAuth2User = super.loadUser(userRequest);
        // OAuth 로그인 버튼 클릭 -> OAuth 로그인 창 -> 로그인 완료 -> code를 리턴(OAuth-Client 라이브러리가 받아줌) -> AccessToken을 요청
        // userRequest 정보 -> loadUser() 함수 호출 -> 구글과 같은 정보 제공자로부터 회원 정보를 받아준다.
        logger.info("Get attributes: {}", oAuth2User.getAttributes());

        OAuth2UserInfo oAuth2UserInfo = null;
        logger.info("{} 로그인 요청", userRequest.getClientRegistration().getRegistrationId());
        if (userRequest.getClientRegistration().getRegistrationId().equals("google")) {
            oAuth2UserInfo = new GoogleUserInfo(oAuth2User.getAttributes());
        } else if (userRequest.getClientRegistration().getRegistrationId().equals("naver")) {
            oAuth2UserInfo = new NaverUserInfo((Map) oAuth2User.getAttributes().get("response"));
        } else {
            logger.info("구글, 네이버 이외의 OAuth 로그인 시도");
            throw new OAuth2AuthenticationException("저희 서비스는 Google, Kakao 로그인만 지원하고 있습니다.");
        }

        String provider = oAuth2UserInfo.getProvider();
        String providerId = oAuth2UserInfo.getProviderId();
        String userId = provider + "_" + Member.createRandomUserId(11 - provider.length());
        String nickname = userId;
        String email = oAuth2UserInfo.getEmail();
        Check check = Check.createCheck();
        check.changeEmailAuth(true);
        check.changeInformationAgree(true);
        Member member = Member.createMember(userId, null, nickname, email, check);
        while(!memberService.findByUserId(member).isEmpty()) {
            member.changeUserId(provider + "_" + Member.createRandomUserId(11 - provider.length()));
            member.changeNickname(member.getUserId());
        }

        List<Member> memberList = memberService.findByEmail(member);
        // 처음 OAuth 로그인 시 강제 회원 가입
        if (memberList.isEmpty()) {
            logger.info("{} 최초 로그인 입니다.", provider);
            member.updateToTemporaryPassword();
            memberService.register(member);
        } else if (memberList.get(0).getUserId().contains(provider)){
            logger.info("이미 {} 로그인을 한 적이 있습니다.", provider);
            member = memberList.get(0);
        }
        else {
            logger.info("이미 동일한 이메일로 회원 가입을 진행한 적이 있습니다.");
            throw new OAuth2AuthenticationException("이미 다른 플랫폼으로 로그인한 적이 있습니다.");
        }

        return new PrincipalDetails(member, oAuth2User.getAttributes());
    }
}
