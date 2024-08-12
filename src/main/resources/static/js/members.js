const FIELD_USER_ID = "userId";
const FIELD_EMAIL = "email";
const FIELD_NICKNAME = "nickname";
const FIELD_EMAIL_NUMBER = "emailNumber";
const FIELD_PASSWORD = "password";
const FIELD_PASSWORD_CONFIRM = "passwordConfirm";
const ERROR_CODE_PATTERN = "Pattern";
const ERROR_CODE_NotEmpty = "NotEmpty";
const ERROR_CODE_EMAIL_NOT_EXIST = "EMAIL_NOT_EXIST";
const ERROR_CODE_AUTH_NUM_NOT_EXIST = "AUTH_NUM_NOT_EXIST";
const ERROR_CODE_USER_NOT_EXIST = "USER_NOT_EXIST";

// 이메일 인증번호 전송을 서버에서 진행할 수 있도록 ajax 요청하는 함수
function emailNumberSend() {
    const email = $("#email").val();
    console.log("emailNumberSend js 호출됨");

    $.ajax({
        url: '/api/registration/emailNumberSend',
        type: 'POST',
        contentType: 'application/json',
        data: JSON.stringify({email: email}),
        success: function (response) {
            if (response.authNumber) {
                console.log('Verification Code:', response.authNumber);
                $("#timeCount").val(response.timeCount); //인증번호 유효시간 설정
                countDown(); //타이머를 시작
                bodyAlert(response.message);
                $('#emailNumber').attr("disabled", false);
                $('#numberCheck').prop('disabled', false);
                $("#email").attr('class', "form-control");
            }
        },
        error: function (xhr, status, error) {
            $('#emailNumber').attr("disabled", true);
            $('#numberCheck').attr("disabled", true);
            hideBodyAlert();
            //console.error('Error:', error);
            if (xhr.responseJSON) {
                // 오류 메시지가 배열 형태로 되어 있는지 확인
                if (Array.isArray(xhr.responseJSON)) {
                    // 여러 오류 메시지가 있는 경우, 첫 번째 메시지만 표시하거나 모든 메시지를 표시
                    if (xhr.responseJSON.length > 0) {
                        let firstError = xhr.responseJSON[0]; // 첫 번째 오류 메시지
                        console.log("emailNumberSend: " + firstError);
                        $("#emailError").text(firstError.message).show();
                        $("#email").attr('class', "form-control fieldError").focus();
                    }
                } else {
                    // 오류 메시지가 배열이 아닌 경우, 단일 객체로 가정하고 처리
                    let err = xhr.responseJSON;
                    $("#emailError").text(err.message).show();
                    $("#email").attr('class', "form-control fieldError").focus();
                }
            } else {
                // xhr.responseJSON이 없는 경우 기본 오류 메시지 표시
                $("#emailError").text("서버 오류가 발생했습니다.").show();
                $("#email").attr('class', "form-control fieldError").focus();
            }
        }
    });
}

// 아이디 찾기 시 이메일 인증번호 전송을 서버에서 진행할 수 있도록 ajax 요청하는 함수
function ExistEmailNumberSend() {
    const email = $("#email").val();
    console.log("emailNumberSend js 호출됨");

    $.ajax({
        url: '/api/recovery/email-number',
        type: 'POST',
        contentType: 'application/json',
        data: JSON.stringify({email: email}),
        success: function (response) {
            if (response.authNumber) {
                console.log('Verification Code:', response.authNumber);
                $("#timeCount").val(response.timeCount); //인증번호 유효시간 설정
                countDown(); //타이머를 시작
                bodyAlert(response.message);
                $('#emailNumber').attr("disabled", false);
                $('#numberCheck').prop('disabled', false);
                $("#email").attr('class', "form-control");
            }
        },
        error: function (error) {
            $('#emailNumber').attr("disabled", true);
            $('#numberCheck').attr("disabled", true);
            hideBodyAlert();
            console.log(error.responseJSON);
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
            console.log(err);
            if (err) message = err.message;
            $("#emailError").text(message).show();
            $("#email").attr('class', "form-control fieldError").focus();
        }
    });
}

// 비밀번호 초기화 시 이메일 인증번호 전송을 서버에서 진행할 수 있도록 ajax 요청하는 함수
function ExistIdEmailNumberSend() {
    let userIdChangeCount = 0, emailChangeCount = 0;
    $('#userId').change(function () {
        userIdChangeCount++;
    });
    $('#email').change(function () {
        emailChangeCount++;
    });
    const userId = $("#userId").val();
    const email = $("#email").val();
    console.log("emailNumberSend js 호출됨");

    $.ajax({
        url: '/api/recovery/id-email-number',
        type: 'POST',
        contentType: 'application/json',
        data: JSON.stringify({userId: userId, email: email}),
        success: function (response) {
            if (response.authNumber) {
                console.log('Verification Code:', response.authNumber);
                $("#timeCount").val(response.timeCount); //인증번호 유효시간 설정
                countDown(); //타이머를 시작
                bodyAlert(response.message);
                $('#emailNumber').attr("disabled", false);
                $('#numberCheck').prop('disabled', false);
                $("#email").attr('class', "form-control");
            }
        },
        error: function (error) {
            $('#emailNumber').attr("disabled", true);
            $('#numberCheck').attr("disabled", true);
            hideBodyAlert();
            console.log(error.responseJSON);
            console.log(error.responseJSON);
            let err = undefined;
            let message = "에러 이유를 찾을 수 없습니다.";
            let userIdError = false, emailError = false;
            console.log(userIdChangeCount, emailChangeCount);
            if (userIdChangeCount) {
                err = error.responseJSON.find(function (err) {
                    return err.field === FIELD_USER_ID && err.code === ERROR_CODE_NotEmpty;
                });
                if (!err) err = error.responseJSON.find(function (err) {
                    return err.field === FIELD_USER_ID && err.code === ERROR_CODE_PATTERN;
                });
                if (err) {
                    console.log(err);
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
                    console.log(err);
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
                    console.log(err);
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
}

var seconds; // 남은 시간 변수
var countdown; // 카운트다운을 관리하는 변수

function countDown() {
    $("#numberSend").text('재전송');

    clearInterval(countdown);
    seconds = $("#timeCount").val();//60 * 30; // 30분(1800초)

    updateCountdown();
    // 1초마다 카운트다운 업데이트
    countdown = setInterval(updateCountdown, 1000);
}

// 시간을 업데이트하고 화면에 표시하는 함수
function updateCountdown() {
    if (seconds >= 0) {
        const minutes = Math.floor(seconds / 60);
        const remainingSeconds = seconds % 60;
        $('#time').text(`${minutes.toString().padStart(2, '0')}:${remainingSeconds.toString().padStart(2, '0')}`);
        document.getElementById("timeCount").value = seconds--;
    } else {
        clearInterval(countdown);
        $("#emailNumber").attr('class', "form-control fieldError").focus();
        $('#verificationCodeError').text('인증 번호 유효 시간이 초과되어 다시 인증 번호를 발급해 주세요.').show();
    }
}

// id가 email인 속성의 값이 변하면 이메일 중복 확인, 이메일 인증 번호 발급, 이메일 인증 번호 검증 여부를 false로 바꾼다. N일 때는 중복 검사 혹은 확인 검사를 먼저 하도록 하는데 쓰인다.
function changeEmail() {
    $('#email').on('change', function () {
        $('#Chk').attr("value", "N");
        $('#emailCheck').prop('checked', false);
        $('#emailNumberCheck').prop('checked', false);
        $('#emailNumberSend').prop('checked', false);
    });
}

// 프론트에서 에러 메시지를 출력하기 전에 기존에 있던 에러를 페이지에서 숨기는 함수이다.
function resetError() {
    $("#userId").attr('class', "form-control");
    if (document.getElementById("thUserIdError")) $('#thUserIdError').hide();
    $("#nickname").attr('class', "form-control");
    if (document.getElementById("thNicknameError")) $('#thNicknameError').hide();
    $("#email").attr('class', "form-control");
    if (document.getElementById("thEmailError")) $('#thEmailError').hide();
    if (document.getElementById("globalError")) $('#globalError').hide();
    if (document.getElementById("memberInfoError")) $('#memberInfoError').hide();
    if (document.getElementById("thGlobalError")) $('#thGlobalError').hide();
    $("#emailNumber").attr('class', "form-control");
    if (document.getElementById("thEmailNumberError")) $('#thEmailNumberError').hide();
    $("#passwordConfirm").attr('class', "form-control");
    if (document.getElementById("thPasswordConfirmError")) $('#thPasswordConfirmError').hide();
    if (document.getElementById("userIdError")) $('#userIdError').hide();
    if (document.getElementById("nicknameError")) $('#nicknameError').hide();
    if (document.getElementById("emailError")) $('#emailError').hide();
    if (document.getElementById("verificationCodeError")) $('#verificationCodeError').hide();
    if (document.getElementById("passwordError")) $('#passwordError').hide();
    if (document.getElementById("thPasswordError")) $('#thPasswordError').hide();
    if (document.getElementById("passwordConfirmError")) $('#passwordConfirmError').hide();
    if (document.getElementById("verificationCodeError")) $('#verificationCodeError').hide();
}

function isEmailEmpty() {
    if ($("#email").val() === "") {
        resetError();
        $("#email").attr('class', "form-control fieldError").focus();
        $('#emailError').text('이메일은 필수입니다.').show();
        return false;
    }
    return true;
}

function isEmailNumberSend() {
    if ($("#emailNumberSend").is(":checked") === false) {
        resetError();
        $('#verificationCodeError').text('먼저 인증번호 발급을 해주세요.').show();
        return false;
    }
    return true;
}

// 이메일 인증 번호 확인을 서버에서 진행할 수 있도록 ajax 요청하는 함수
function emailNumberChk() {
    console.log("emailNumberChk js 호출됨");
    if (seconds <= 0) {
        updateCountdown();
        return false;
    }
    // 이메일과 인증 번호 값 가져오기
    const email = $("#email").val();
    const authNum = $("#emailNumber").val();

    // AJAX 요청 보내기
    $.ajax({
        url: '/api/registration/emailNumberChk', // 요청할 URL
        type: 'POST',
        contentType: 'application/json',
        data: JSON.stringify({email: email, authNum: authNum}), // 요청 데이터
        success: function (response) {
            if (response.emailNumberCheck) {
                $('#verificationCodeError').hide();
                if ($("#emailNumber").is(":focus")) {
                    $("#emailNumber").blur();
                }
                $("#emailNumber").attr('class', "form-control");
                bodyAlert(response.message);
                console.log('인증 번호가 일치합니다.');
                $('#registerSubmit').prop('disabled', false);
                clearInterval(countdown);
                $("#time").text(''); // 시간을 초기화
            }
        },
        error: function (xhr, status, error) {
            if (xhr.responseJSON) {
                // 오류 메시지가 배열 형태로 되어 있는지 확인
                if (Array.isArray(xhr.responseJSON)) {
                    // 여러 오류 메시지가 있는 경우, 첫 번째 메시지만 표시하거나 모든 메시지를 표시
                    if (xhr.responseJSON.length > 0) {
                        let firstError = xhr.responseJSON[0]; // 첫 번째 오류 메시지
                        console.log("emailNumberChk: " + firstError.message);
                        $("#verificationCodeError").text(firstError.message).show();
                        $("#emailNumber").attr('class', "form-control fieldError").focus();
                    }
                } else {
                    // 오류 메시지가 배열이 아닌 경우, 단일 객체로 가정하고 처리
                    let err = xhr.responseJSON;
                    $("#verificationCodeError").text(err.message).show();
                    $("#emailNumber").attr('class', "form-control fieldError").focus();
                }
            } else {
                // xhr.responseJSON이 없는 경우 기본 오류 메시지 표시
                $("#verificationCodeError").text("서버 오류가 발생했습니다.").show();
                $("#emailNumber").attr('class', "form-control fieldError").focus();
            }
        }
    });
}

let firstRequest = 0; //첫 번째 요청인지 판단하기 위한 변수
//패스워드 관련 로직을 서버에서 진행할 수 있도록 ajax 요청하는 함수
function checkPassword() {
    const password = $("#password").val();
    const passwordConfirm = $("#passwordConfirm").val();
    firstRequest++;
    console.log("checkPassword js 호출됨");

    // AJAX 요청 보내기
    $.ajax({
        url: '/api/registration/check/password', // 요청할 URL
        type: 'POST',
        contentType: 'application/json',
        data: JSON.stringify({password: password, passwordConfirm: passwordConfirm}), // 요청 데이터
        success: function (response) {
            $('#passwordError').hide();
            $('#passwordConfirmError').hide();
            if ($("#password").is(":focus")) {
                $("#password").blur();
            }
            if ($("#passwordConfirm").is(":focus")) {
                $("#passwordConfirm").blur();
            }
            $("#password").attr('class', "form-control");
            $("#passwordConfirm").attr('class', "form-control");
            bodyAlert(response.message);
        },
        error: function (xhr, status, error) {
            if (xhr.responseJSON) {
                // 오류 메시지가 배열 형태로 되어 있는지 확인
                if (Array.isArray(xhr.responseJSON)) {
                    // 여러 오류 메시지가 있는 경우, 첫 번째 메시지만 표시하거나 모든 메시지를 표시
                    if (xhr.responseJSON.length > 0 && xhr.status === 400) {
                        let firstError = xhr.responseJSON[0]; // 첫 번째 오류 메시지
                        console.log("checkPassword: " + firstError.message);
                        $("#password").attr('class', "form-control fieldError").focus();
                        $("#passwordConfirm").attr('class', "form-control");
                        $("#passwordError").text(firstError.message).show();
                        $('#passwordConfirmError').hide();
                    }
                    else if(xhr.responseJSON.length > 0 && xhr.status === 409 && firstRequest !== 1) {
                        //첫 번째 요청이 아닌 경우에는 에러 메시지를 보여주지 않음
                        let firstError = xhr.responseJSON[0]; // 첫 번째 오류 메시지
                        console.log("checkPassword: " + firstError.message);
                        $("#passwordConfirm").attr('class', "form-control fieldError").focus();
                        $("#password").attr('class', "form-control");
                        $("#passwordConfirmError").text(firstError.message).show();
                        $('#passwordError').hide();
                    }
                } else {
                    // 오류 메시지가 배열이 아닌 경우, 단일 객체로 가정하고 처리
                    if (xhr.status === 400) {
                        let err = xhr.responseJSON;
                        $("#password").attr('class', "form-control fieldError").focus();
                        $("#passwordConfirm").attr('class', "form-control");
                        $("#passwordError").text(err.message).show();
                        $('#passwordConfirmError').hide();
                    }
                    else if(xhr.status === 409 && firstRequest !== 1) {
                        let err = xhr.responseJSON;
                        $("#passwordConfirm").attr('class', "form-control fieldError").focus();
                        $("#password").attr('class', "form-control");
                        $("#passwordConfirmError").text(err.message).show();
                        $('#passwordError').hide();
                    }
                }
            } else {
                // xhr.responseJSON이 없는 경우 기본 오류 메시지 표시
                $("#passwordConfirmError").text("서버 오류가 발생했습니다.").show();
            }
        }
    });
}

// 이메일 인증 번호 섹션을 비활성화하는 함수이다.
function disableEmailNumberSection() {
    $("#verificationCodeError").hide();
    $("#numberSend").text('인증번호 발급').attr("disabled", true);
    $("#emailNumber").attr('class', "form-control").val("").attr("disabled", true);
    $("#numberCheck").attr("disabled", true);
    clearInterval(countdown);
    $("#time").text("");
    $("#timeCount").text("");
}