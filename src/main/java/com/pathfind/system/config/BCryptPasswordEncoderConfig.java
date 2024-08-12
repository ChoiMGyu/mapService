/*
 * 클래스 기능 : BCryptPasswordEncoder config class. 비밀번호 암호화에 사용된다. 스프링 시큐리티 사용 시 비밀번호가 암호화된 상태로 db에 저장되어야 하기 때문에 사용한다.
 * 최근 수정 일자 : 2024.05.19(일)
 */
package com.pathfind.system.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Configuration
public class BCryptPasswordEncoderConfig {
    // 해당 메서드의 리턴되는 오브젝트를 IoC로 등록해준다.
    @Bean
    public BCryptPasswordEncoder encodePwd() {
        return new BCryptPasswordEncoder();
    }
}
