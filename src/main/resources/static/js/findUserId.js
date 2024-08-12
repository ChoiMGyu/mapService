// 이메일 중복 여부 및 유효성 확인을 서버에서 진행할 수 있도록 form을 전송하는 함수
function emailExist() {

    $('#email').change(function () {
        disableEmailNumberSection();
        //resetError();
        //if (!isEmailEmpty()) return false;
        const email = $("#email").serialize();
        //console.log(email);
        $.ajax({
            type: "GET",
            url: "/api/recovery/exist/email?" + email,
            success: function (response) {
                //console.log(response);
                $("#emailError").hide();
                $("#email").attr('class', "form-control").focus();
                $("#numberSend").attr("disabled", false);
                bodyAlert(response.message);
            },
            error: function (error) {
                //console.log(error.responseJSON);
                let err;
                let message = "에러 이유를 찾을 수 없습니다.";
                err = error.responseJSON.find(function (err) {
                    return err.field === FIELD_EMAIL && err.code === ERROR_CODE_NotEmpty;
                });
                if (!err) err = error.responseJSON.find(function (err) {
                    return err.field === FIELD_EMAIL && err.code === ERROR_CODE_PATTERN;
                });
                if (!err) err = error.responseJSON.find(function (err) {
                    return err.code === ERROR_CODE_EMAIL_NOT_EXIST;
                });
                //console.log(err);
                if (err) message = err.message;
                $("#emailError").text(message).show();
                $("#email").attr('class', "form-control fieldError").focus();
            }
        });
    });
}

// 이메일 인증 번호 확인을 서버에서 진행할 수 있도록 form을 전송하는 함수
function EmailAndEmailNumberChk() {
    // if (!isEmailNumberSend()) {
    //     //console.log("return됨");
    //     return false;
    // }
    resetError();
    //if (!isEmailEmpty()) return false;
    const authNum = $("#emailNumber").serialize();
    //console.log(authNum);
    if (seconds <= 0) {
        //console.log("여기 진입");
        updateCountdown();
        return false;
    }
    // 이메일과 인증 번호 값 가져오기
    const email = $("#email").serialize();
    const emailNumber = $("#emailNumber").serialize();
    const query = email + "&" + emailNumber;
    //console.log("form : " + query);

    // AJAX 요청 보내기
    $.ajax({
        url: '/api/recovery/userid?' + query, // 요청할 URL
        type: 'GET',
        contentType: 'application/json',
        success: function (response, success, xhr) {
            //console.log(response);
            if (response.recoverySuccess === true) {
                window.location.href = "/members/returnId?userId=" + response.userId;
            } else {
                $("#verificationCodeError").text(response.message).show();
            }
        },
        error: function (error) {
            //console.log(error.responseJSON);
            let err;
            let message = "에러 이유를 찾을 수 없습니다.";
            err = error.responseJSON.find(function (err) {
                return err.field === FIELD_EMAIL_NUMBER && err.code === ERROR_CODE_NotEmpty;
            });
            if (!err) err = error.responseJSON.find(function (err) {
                return err.field === FIELD_EMAIL_NUMBER && err.code === ERROR_CODE_PATTERN;
            });
            if (!err) err = error.responseJSON.find(function (err) {
                return err.code === ERROR_CODE_AUTH_NUM_NOT_EXIST;
            });
            //console.log(err);
            if (err) message = err.message;
            $("#verificationCodeError").text(message).show();
            $("#emailNumber").attr('class', "form-control fieldError").focus();
        }
    });
}

emailExist();