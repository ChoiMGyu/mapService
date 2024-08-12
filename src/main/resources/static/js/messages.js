// 서버 측으로부터 message가 있으면 해당 메시지를 담은 알림창을 띄워준다.
document.addEventListener("DOMContentLoaded", function () {
    var messageElement = document.querySelector('.alert');
    if (messageElement) {
        setTimeout(function () {
            messageElement.style.display = 'none';
        }, 5000); // 5000 milliseconds (5 seconds)
    }
});

function bodyAlert(message = "") {
    let id = Math.floor(Math.random() * 1e9).toString();
    $("#bodyAlertSection").append(
        "<div id='" + id + "' class='alert alert-info alert-dismissible fade show m-2' role='alert' style='opacity: 97%'>" +
        "   <span class='text-start fs-6'>" + message + "</span>" +
        "   <button type='button' class='btn-close messageBtn' data-dismiss='modal' aria-label='Close' onclick='$(\"#" + id + "\").remove();'></button>" +
        "</div>"
    );
    setTimeout(function () {
        $("#" + id).remove();
    }, 5000); // 5000 milliseconds (5 seconds)
}

function hideBodyAlert() {
    $("#bodyAlertSection").empty();
}
