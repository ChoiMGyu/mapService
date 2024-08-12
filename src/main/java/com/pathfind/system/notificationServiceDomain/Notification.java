/*
 * 클래스 기능 : 알림 정보를 구현한 클래스
 * 최근 수정 일자 : 2024.05.28(화)
 */
package com.pathfind.system.notificationServiceDomain;

import lombok.*;

import java.util.UUID;

@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@ToString
public class Notification {
    private String id;
    private String content;
    private String url;
    private String roomId;
    private String senderUserId;
    private String receiverUserId;
    private ReadType readType = ReadType.NOT_READ;
    private NotificationType notificationType;

    @Builder(builderMethodName = "innerBuilder")
    private Notification(String content, String url, String roomId, String senderUserId, String receiverUserId, NotificationType notificationType) {
        this.id = UUID.randomUUID().toString();
        this.content = content;
        this.url = url;
        this.roomId = roomId;
        this.senderUserId = senderUserId;
        this.receiverUserId = receiverUserId;
        this.notificationType = notificationType;
    }

    public static NotificationBuilder builder(String content, String senderNickname, String receiverNickname, NotificationType notificationType) {
        return innerBuilder().content(content).senderUserId(senderNickname).receiverUserId(receiverNickname).notificationType(notificationType);
    }

    public void changeReadTypeToREAD() {
        this.readType = ReadType.READ;
    }
}
