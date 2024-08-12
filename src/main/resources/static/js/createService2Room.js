/**
 * 서비스 2의 길 찾기 방을 생성하기 위해 사용되는 함수이다.
 */
function createService2Room() {
    let roomName = $("#roomName").val();
    let transportationType = $("#transportation").val();
    const csrfToken = document.getElementById('_csrf').value;
    $.ajax({
        type: "POST",
        url: "/service2/create-room",
        beforeSend: function(xhr) {
            xhr.setRequestHeader('X-CSRF-TOKEN', csrfToken);
        },
        data: {
            roomName: roomName,
            transportationType: transportationType
        },
        success: function (response) {
            /*console.log(response);
            console.log("success to create New room. roomName: ", roomName);*/
            location.replace(response);
        },
        error: function (error) {
            //console.log(error.responseJSON.message);
            if(error.responseJSON.message != null) {
                let form = document.createElement("form");
                form.name = "createRoom";
                form.action = "/";
                form.method = "get";
                form.style.display = 'none';

                let input = document.createElement("input");
                input.value = error.responseJSON.message;
                input.name = "message";
                form.appendChild(input);

                document.body.appendChild(form);
                form.submit();
            }
            error.responseJSON.find(function (err) {
                $("#roomNameError").text(err.message).show();
                $("#roomName").attr('class', "form-control fieldError").focus();
            });
        }
    });
}