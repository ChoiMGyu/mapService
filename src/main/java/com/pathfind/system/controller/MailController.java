/*
 * 클래스 기능 : 이메일 인증 절차를 위한 이메일 전송과 인증 절차를 수행하는 컨트롤러
 * 최근 수정 일자 : 2024.07.22(월)
 */
package com.pathfind.system.controller;

import com.pathfind.system.memberDto.EmailCheckDto;
import com.pathfind.system.memberDto.EmailNumVCRequest;
import com.pathfind.system.service.MailSendService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController //RESTful API로 설계(Postman으로 동작 확인)
//다른 프로그램에서 이 동작을 사용할 수 있게 하기 위함
@RequiredArgsConstructor
public class MailController {

    private static final Logger logger = LoggerFactory.getLogger(MailController.class);
    //로그를 info 레벨로 출력

    private final MailSendService mailService;

    @PostMapping("/mailSend")
    public String mailSend(@RequestBody @Valid EmailNumVCRequest emailDto){
        //이메일 인증을 수행하기 위해 이메일 인증 요청 메일을 사용자에게 전송
        //System.out.println("이메일 인증 이메일 :"+emailDto.getEmail());
        logger.info("이메일 인증 이메일 : " + emailDto.getEmail());
        return mailService.joinEmail(emailDto.getEmail());
    }

    @PostMapping("/mailauthCheck")
    public String AuthCheck(@RequestBody @Valid EmailCheckDto emailCheckDto){
        //이메일 인증을 확인하기 위한 인증번호 확인
        logger.info("이메일 인증 요청 이메일 : " + emailCheckDto.getEmail() + ", 이메일 인증 입력받은 인증번호 : " + emailCheckDto.getAuthNum());
        Boolean Checked = mailService.CheckAuthNum(emailCheckDto.getEmail(),emailCheckDto.getAuthNum());
        if(Checked){
            return "ok";
        }
        else{
            throw new NullPointerException("잘못된 부분이 존재합니다.");
        }
    }
}
