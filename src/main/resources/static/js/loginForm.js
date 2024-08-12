// 로그인 폼을 json 형식으로 보내는 함수이다. jwt 사용 시 json 형식으로 값을 받기 때문에 해당 함수를 사용한다.
function submitLoginForm() {
    $("#loginFormSubmit").on("click", function () {
        let userId = $("#userId").val();
        let password = $("#password").val();
        $.ajax({
            url: '/members/login',
            type: 'POST',
            contentType: 'application/json',
            data: JSON.stringify({userId: userId, password: password}),
            success: function (response, textStatus, xhr) {
/*                console.log(response);
                console.log(textStatus);
                console.log(xhr);
                console.log(xhr.getResponseHeader("Authorization"));

                localStorage.setItem("Authorization", xhr.getResponseHeader("Authorization"));*/
                window.location.href = "/";
            },
            error: function (error) {
                console.log(error);
                console.log(error.responseJSON);
                let message = error.responseJSON.message;
                $("#loginError").text(message).show();
            }
        });
    });
}

submitLoginForm();