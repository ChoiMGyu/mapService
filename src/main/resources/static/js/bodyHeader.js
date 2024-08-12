const READ = "READ", NOT_READ = "NOT_READ";

/**
 * 알림들의 readType을 READ로 변경시키는 함수이다.
 */
function changeAllReadTypeToReadByUserId(userId) {
    let hasNotRead = 0;
    $(".notificationItem").each(function (index, element) {
        if ($(element).attr("value") === NOT_READ) {
            hasNotRead = 1;
        }
    });
    if (!hasNotRead) return;
    $.ajax({
        type: "GET",
        url: "/notification/check",
        async: false,
        data: {
            userId: userId
        },
        success: function (response) {
            console.log(response);
            $("#newNotifications").hide();
        },
        error: function (error) {
            console.log(error);
        }
    });
}

/**
 * document가 모두 로드된 뒤 sse connection을 생성하는 코드이다.
 */
$(document).ready(function () {
    const protocol = window.location.protocol;
    const host = window.location.host;
    const eventSource = new EventSource(protocol + "//" + host + "/notification/subscribe?userId=" + $("#headerUserId").attr("value"));
    //console.log(protocol + "//" + host + "/notification/subscribe?userId=" + $("#headerUserUserId").attr("value"));
    eventSource.onmessage = (event) => {
        //console.log(event);
        let notification;
        try {
            notification = JSON.parse(event.data);
        } catch (e) {
            return;
        }
        if (notification.readType === NOT_READ) {
            $("#newNotifications").show();
        }
        $("#defaultNotification").hide();
        //console.log(notification);
        $("#notifications").prepend(
            "<li onselectstart='return false' class='notificationItem' value='" + notification.readType + "'>" +
            "   <a class='list-group-item list-group-item-action' href=" + notification.url + ">" +
            "       <small>" + notification.content + "</small>" +
            "   </a>" +
            "</li>"
        ); // 한 개의 알림을 li 선택자를 이용해 리스트로 만들어 추가한다.
    };
});