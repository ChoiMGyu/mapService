// 아이디 중복 여부 및 유효성 확인을 서버에서 진행할 수 있도록 ajax를 사용해 userId를 전송하는 함수
function checkUserId() {
    let userId = $("#userId").val();
    console.log("checkUserId js 호출됨");
    $.ajax({
        url: "/api/registration/check/user-id?userId=" + userId,
        type: 'GET',
        success: function(response) {
            $('#userIdError').hide();
            if ($("#userId").is(":focus")) {
                $("#userId").blur(); // userId 필드의 포커스 해제
            }
            $("#userId").attr('class', "form-control");
            bodyAlert(response.message);
        },
        error: function(error) {
            error.responseJSON.find(function (err) {
                console.log(err);
                $("#userIdError").text(err.message).show();
                $("#userId").attr('class', "form-control fieldError").focus();
            });
        }
    });
}

// 닉네임 중복 여부 및 유효성 확인을 서버에서 진행할 수 있도록 form을 전송하는 함수
function checkNickname() {
    let nickname = $("#nickname").val();
    console.log("checkNickname js 호출됨");
    $.ajax({
        url: "/api/registration/check/nickname?nickname=" + nickname,
        type: 'GET',
        success: function(response) {
            $('#nicknameError').hide();
            if ($("#nickname").is(":focus")) {
                $("#nickname").blur(); // userId 필드의 포커스 해제
            }
            $("#nickname").attr('class', "form-control");
            bodyAlert(response.message);
        },
        error: function(error) {
            error.responseJSON.find(function (err) {
                console.log(err);
                $("#nicknameError").text(err.message).show();
                $("#nickname").attr('class', "form-control fieldError").focus();
            });
        }
    });
}

// 이메일 중복 여부 및 유효성 확인을 서버에서 진행할 수 있도록 form을 전송하는 함수
function checkEmail() {
    disableEmailNumberSection();
    let email = $("#email").val();
    console.log("checkEmail js 호출됨");

    $.ajax({
        url: "/api/registration/check/email?email=" + email,
        type: 'GET',
        success: function(response) {
            $('#emailError').hide();
            if ($("#email").is(":focus")) {
                $("#email").blur(); // userId 필드의 포커스 해제
            }
            $("#email").attr('class', "form-control");
            $('#emailNumber').prop('disabled', false);
            $('#numberSend').prop('disabled', false);
            bodyAlert(response.message);
        },
        error: function(error) {
            disableEmailNumberSection();
            error.responseJSON.find(function (err) {
                console.log(err);
                $("#emailError").text(err.message).show();
                $("#email").attr('class', "form-control fieldError").focus();
            });
        }
    });
}

//회원 가입 버튼을 눌러서 회원 가입을 진행하는 ajax 호출 함수
function checkRegister() {
    let userId = $("#userId").val();
    let nickname = $("#nickname").val();
    let email = $("#email").val();
    let authNum = $("#emailNumber").val();
    let password = $("#password").val();
    let passwordConfirm = $("#passwordConfirm ").val();

    $.ajax({
        url: "/api/registration/register",
        type: 'POST',
        contentType: 'application/json',
        data: JSON.stringify({ userId: userId, nickname: nickname, email: email, authNum: authNum, password: password, passwordConfirm: passwordConfirm }), // 요청 데이터
        success: function(response) {
            resetError();
            if(response.registerCheck) {
                window.location.href = "/members/registerComplete"; //회원가입 완료 페이지로 리다이렉트
            }
            else {
                bodyAlert(response.message);
            }
        },
        error: function(xhr, status, error) {
            if (xhr.responseJSON) {
                // 오류 메시지가 배열 형태로 되어 있는지 확인
                if (Array.isArray(xhr.responseJSON)) {
                    // 여러 오류 메시지가 있는 경우, 첫 번째 메시지만 표시하거나 모든 메시지를 표시
                    if (xhr.responseJSON.length > 0) {
                        let firstError = xhr.responseJSON[0]; // 첫 번째 오류 메시지
                        console.log("첫번째 에러 메시지: " + firstError.message);
                        bodyAlert(firstError.message);
                    }
                } else {
                    // 오류 메시지가 배열이 아닌 경우, 단일 객체로 가정하고 처리
                    let err = xhr.responseJSON;
                    bodyAlert(err.message);
                }
            } else {
                // xhr.responseJSON이 없는 경우 기본 오류 메시지 표시
                bodyAlert("서버 오류가 발생했습니다.");
            }
        }
    });
}