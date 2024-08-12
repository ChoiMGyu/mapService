/*
 * 클래스 기능 : 이메일 인증 서비스 인터페이스
 * 최근 수정 일자 : 2024.08.02(금)
 */
package com.pathfind.system.service;

public interface MailSendService {

    public void makeRandomNumber(); //인증번호를 랜덤으로 생성

    public String joinEmail(String email);
    //mail을 어디서 보내는지, 어디로 보내는지 , 인증 번호를 html 형식으로 어떻게 보내는지 작성

    public void findPasswordEmail(String email, String TemporaryPassword);

    public void mailSend(String setFrom, String toMail, String title, String content);
    //이메일을 생성(setFrom)하여 사용자에게 전송(toMail)

    public boolean CheckAuthNum(String email,String authNum);
    //이메일과 인증번호를 확인

    public boolean deleteEmail(String email, String authNum);
    //이메일과 인증번호를 확인하여 동일할 경우 Redis에서 이메일과 인증번호 삭제
}
