/*
 * 클래스 기능 : 알림 정보를 사용자에게 전송할 때 사용되는 dto
 * 최근 수정 일자 : 2024.04.04(수)
 */
package com.pathfind.system.notificationServiceDto;

import com.pathfind.system.notificationServiceDomain.NotificationType;
import com.pathfind.system.notificationServiceDomain.ReadType;
import lombok.*;

@Getter
@Builder(builderMethodName = "innerBuilder")
@ToString
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor(access = AccessLevel.PROTECTED)
public class NotificationVCResponse {
    private String content;
    private String url;
    private String roomId;
    private String senderNickname;
    private String receiverNickname;
    private ReadType readType;
    private NotificationType notificationType;

    public static NotificationVCResponseBuilder builder(String content, String senderNickname, String receiverNickname, ReadType readType, NotificationType notificationType) {
        return innerBuilder().content(content).senderNickname(senderNickname).receiverNickname(receiverNickname).readType(readType).notificationType(notificationType);
    }
}
