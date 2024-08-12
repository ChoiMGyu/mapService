/*
 * 클래스 기능 : 이메일 인증 서비스 구현체
 * 최근 수정 일자 : 2024.08.02(금)
 */
package com.pathfind.system.service;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

import java.util.Random;

@Service
public class MailSendServiceImpl implements MailSendService{

    @Autowired
    private JavaMailSender mailSender;
    @Autowired
    private RedisUtil redisUtil;

    private int authNumber; //서버에서 만든 인증번호

    @Value("${api-key.sender-email}")
    String senderEmail;

    private static final Logger logger = LoggerFactory.getLogger(MailSendServiceImpl.class);

    public boolean CheckAuthNum(String email,String authNum){
        logger.info("CheckAuthNum - email: " + email + ", authNum: " + authNum);
        if(redisUtil.getData(email)==null){
            return false;
        }
        else return redisUtil.getData(email).equals(authNum);
    }

    public boolean deleteEmail(String email, String authNum) {
        if(redisUtil.getData(email)==null){
            logger.info("deleteEmail - " + email + "이라는 키가 존재하지 않음");
            return false;
        }
        if(redisUtil.getData(email).equals(authNum)) {
            redisUtil.deleteData(email);
            return true;
        }
        return false;
    }

    //임의의 6자리 양수를 반환합니다.
    public void makeRandomNumber() {
        Random r = new Random();
        String randomNumber = "";
        for(int i = 0; i < 6; i++) {
            randomNumber += Integer.toString(r.nextInt(10));
        }

        authNumber = Integer.parseInt(randomNumber);
    }


    //mail을 어디서 보내는지, 어디로 보내는지 , 인증 번호를 html 형식으로 어떻게 보내는지 작성합니다.
    public String joinEmail(String email) {
        makeRandomNumber();
        String setFrom = senderEmail; // email-config에 설정한 자신의 이메일 주소를 입력
        String toMail = email;
        String title = "회원 가입 인증 이메일 입니다."; // 이메일 제목
        String content =
                "나의 APP을 방문해주셔서 감사합니다." + 	//html 형식으로 작성 !
                        "<br><br>" +
                        "인증 번호는 " + authNumber + "입니다." +
                        "<br>" +
                        "인증번호를 제대로 입력해주세요"; //이메일 내용 삽입
        mailSend(setFrom, toMail, title, content);
        return Integer.toString(authNumber);
    }

    /**
     * 발급된 임시 비밀번호를 사용자에게 이메일로 보내는 함수.
     */
    public void findPasswordEmail(String email, String TemporaryPassword) {
        String setForm = senderEmail;
        String toMail = email;
        String title = "나의 APP 임시 비밀번호 발급";
        String content =
                "나의 APP을 방문해주셔서 감사합니다.<br>" +
                        "비밀번호 찾기에 따른 임시 비밀번호를 알려드립니다.<br>" +
                        "임시 비밀 번호: " + TemporaryPassword + "<br>" +
                        "로그인 후 꼭 비밀번호를 변경해 주세요.";
        mailSend(setForm,toMail,title,content);
    }

    //이메일을 전송합니다.
    public void mailSend(String setFrom, String toMail, String title, String content) {
        MimeMessage message = mailSender.createMimeMessage();//JavaMailSender 객체를 사용하여 MimeMessage 객체를 생성
        try {
            MimeMessageHelper helper = new MimeMessageHelper(message,true,"utf-8");//이메일 메시지와 관련된 설정을 수행합니다.
            // true를 전달하여 multipart 형식의 메시지를 지원하고, "utf-8"을 전달하여 문자 인코딩을 설정
            helper.setFrom(setFrom);//이메일의 발신자 주소 설정
            helper.setTo(toMail);//이메일의 수신자 주소 설정
            helper.setSubject(title);//이메일의 제목을 설정
            helper.setText(content,true);//이메일의 내용 설정 두 번째 매개 변수에 true를 설정하여 html 설정으로한다.
            mailSender.send(message);
            redisUtil.setDataExpire(toMail, Integer.toString(authNumber), MailSendValue.AUTH_NUM_DURATION); //추가한 사람 choi 이유) Redis에 저장되는 값이 없어서 (key,value)형태로 저장
        } catch (MessagingException e) {//이메일 서버에 연결할 수 없거나, 잘못된 이메일 주소를 사용하거나, 인증 오류가 발생하는 등 오류
            // 이러한 경우 MessagingException이 발생
            e.printStackTrace();//e.printStackTrace()는 예외를 기본 오류 스트림에 출력하는 메서드
        }
    }

}
