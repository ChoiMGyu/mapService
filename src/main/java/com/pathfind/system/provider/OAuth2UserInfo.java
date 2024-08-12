/*
 * 클래스 기능 : Provider(구글, 네이버, 카카오 등)에게서 받아온 유저 정보를 담기 위한 interface
 * 최근 수정 일자 : 2024.05.19(일)
 */
package com.pathfind.system.provider;

public interface OAuth2UserInfo {

    public String getProviderId();

    public String getProvider();

    public String getEmail();

    public String getName();

}
