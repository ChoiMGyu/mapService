/*
 * 클래스 기능 : 회원 가입 관련 확인 성공 시 반환할 메시지들을 모아놓는 클래스
 * 최근 수정 일자 : 2024.08.04(일)
 */
package com.pathfind.system.api;

public abstract class CheckMessage {
    public static final String USER_ID = "아이디 중복 확인을 통과하였습니다.";
    public static final String NICKNAME = "닉네임 중복 확인을 통과하였습니다.";
    public static final String EMAIL = "이메일 중복 확인을 통과하였습니다.";
    public static final String EMAIL_SUCCESS = "존재하는 이메일입니다.";
    public static final String FIND_USER_ID_SUCCESS = "아이디 찾기에 성공하였습니다.";
    public static final String ID_EMAIL_SUCCESS = "회원 정보 확인을 통과하였습니다.";
    public static final String RESET_PASSWORD_SUCCESS = "비밀번호가 초기화되었습니다.";
    public static final String AUTHENTICATION_NUM = "인증 번호를 발급하였습니다.";
    public static final String AUTHENTICATION_CHK = "인증 번호 확인을 통과하였습니다.";
    public static final String REGISTER_SUCCESS = "회원 가입을 축하드립니다.";
    public static final String PASSWORD = "비밀 번호 확인을 통과하였습니다.";

    public static final String REGISTER_FAIL = "회원 가입을 실패하였습니다.";
    // public static final String ID_EMAIL_FAIL = "회원정보가 일치하지 않습니다.";
    public static final String RESET_PASSWORD_FAIL = "비밀번호 초기화에 실패하였습니다.";
    // public static final String EMAIL_FAIL = "존재하지 않는 이메일입니다.";
    public static final String FIND_USER_ID_FAIL = "아이디 찾기에 실패하였습니다.";
}
