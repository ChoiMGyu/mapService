// 아이디, 이메일 중복 여부 및 유효성 확인을 서버에서 진행할 수 있도록 form을 전송하는 함수
function idEmailExist() {
    let userIdChangeCount = 0, emailChangeCount = 0;
    $('#userId').change(function () {
        userIdChangeCount++;
    });
    $('#email').change(function () {
        emailChangeCount++;
    });
    //if(!isUserIdEmpty() || !isEmailEmpty()) return false;
    $('#email, #userId').change(function () {
        disableEmailNumberSection();
        if ($("#memberInfoError").css("display") !== "none") {
            //console.log("faesfasfsaefasef");
            if ($("#userIdError").css("display") === "none") {
                $("#userId").attr('class', "form-control");
            }
            if ($("#emailError").css("display") === "none") {
                $("#email").attr('class', "form-control");
            }
            $("#memberInfoError").hide();
        }
        //if (!isEmailEmpty()) return false;
        const userId = $("#userId").serialize();
        const email = $("#email").serialize();
        const query = userId + "&" + email;
        //console.log(query);
        $.ajax({
            type: "GET",
            url: "/api/recovery/exist/id-email?" + query,
            success: function (response) {
                //console.log(response);
                $('#userIdError').hide();
                $("#userId").attr('class', "form-control");
                $('#emailError').hide();
                $("#email").attr('class', "form-control");
                $("#memberInfoError").hide();
                $("#numberSend").attr("disabled", false);
                bodyAlert(response.message);
            },
            error: function (error) {
                //console.log(error.responseJSON);
                let err = undefined;
                let message = "에러 이유를 찾을 수 없습니다.";
                let userIdError = false, emailError = false;
                //console.log(userIdChangeCount, emailChangeCount);
                if (userIdChangeCount) {
                    err = error.responseJSON.find(function (err) {
                        return err.field === FIELD_USER_ID && err.code === ERROR_CODE_NotEmpty;
                    });
                    if (!err) err = error.responseJSON.find(function (err) {
                        return err.field === FIELD_USER_ID && err.code === ERROR_CODE_PATTERN;
                    });
                    if (err) {
                        //console.log(err);
                        message = err.message;
                        $("#userIdError").text(message).show();
                        $("#userId").attr('class', "form-control fieldError").focus();
                        userIdError = true;
                    } else {
                        $("#userIdError").hide();
                        $("#userId").attr('class', "form-control");
                    }
                }
                if (emailChangeCount) {
                    err = error.responseJSON.find(function (err) {
                        return err.field === FIELD_EMAIL && err.code === ERROR_CODE_NotEmpty;
                    });
                    if (!err) err = error.responseJSON.find(function (err) {
                        return err.field === FIELD_EMAIL && err.code === ERROR_CODE_PATTERN;
                    });
                    if (err) {
                        //console.log(err);
                        message = err.message;
                        $("#emailError").text(message).show();
                        $("#email").attr('class', "form-control fieldError").focus();
                        emailError = true;
                    } else {
                        $("#emailError").hide();
                        $("#email").attr('class', "form-control");
                    }
                }
                if (!userIdError && !emailError && userIdChangeCount && emailChangeCount) {
                    err = error.responseJSON.find(function (err) {
                        return err.code === ERROR_CODE_USER_NOT_EXIST;
                    });
                    if (err) {
                        //console.log(err);
                        message = err.message;
                        $("#memberInfoError").text(message).show();
                        $("#userId").attr('class', "form-control fieldError");
                        $("#email").attr('class', "form-control fieldError");
                    } else {
                        $("#memberInfoError").text(message).show();
                    }
                }
            }
        });
    });
}

// 이메일 인증 번호 확인을 서버에서 진행할 수 있도록 form을 전송하는 함수
function resetPassword() {
    //resetError();
    //if (!isEmailEmpty()) return false;
    const authNum = $("#emailNumber").serialize();
    //console.log(authNum);
    //resetError();
    bodyAlert("잠시만 기다려주세요...");
    // if (!isEmailNumberSend()) {
    //     //console.log("return됨");
    //     return false;
    // }
    if (seconds <= 0) {
        //console.log("여기 진입");
        updateCountdown();
        return false;
    }
    // 이메일과 인증 번호 값 가져오기
    const userId = $("#userId").val();
    const email = $("#email").val();
    const emailNumber = $("#emailNumber").val();

    // AJAX 요청 보내기
    $.ajax({
        url: '/api/recovery/password', // 요청할 URL
        type: 'POST',
        contentType: 'application/json',
        data: JSON.stringify({
            userId: userId,
            email: email,
            emailNumber: emailNumber
        }),
        success: function (response, success, xhr) {
            //console.log(response);
            if (response.recoverySuccess === true) {
                window.location.href = "/members/yourPassword";
            } else {
                $("#verificationCodeError").text(response.message).show();
            }
        },
        error: function (error) {
            hideBodyAlert();
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

idEmailExist();
