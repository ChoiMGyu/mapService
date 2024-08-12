/*
 * 클래스 기능 : 계정 복구 API controller
 * 최근 수정 일자 : 2024.08.05(월)
 */
package com.pathfind.system.api;

import com.pathfind.system.customAnnotation.ApiErrorCode;
import com.pathfind.system.domain.Member;
import com.pathfind.system.exception.*;
import com.pathfind.system.memberDto.*;
import com.pathfind.system.service.MailSendService;
import com.pathfind.system.service.MailSendValue;
import com.pathfind.system.service.MemberService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.Parameters;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.*;

@Tag(name = "계정 복구 API", description = "계정 복구 시 사용되는 API")
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/recovery/*")
public class AccountRecoveryApiController {

    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    private final MemberService memberService;

    private final MailSendService mailSendService;

    // 아이디 찾기 시 이메일 유효성 검증, 존재 여부를 검사하는 함수이다.
    @Operation(summary = "이메일 유효성 검증, 존재 여부 확인", description = "아이디 찾기 시 이메일 유효성 검증, 존재 여부를 확인하고 그 결과를 반환합니다.")
    @ApiErrorCode(EmailExistErrorCode.class)
    @GetMapping("/exist/email")
    public EmailExistVCResponse isValidEmail(@Parameter(name = "email", description = "문자열 형태의 이메일") @ModelAttribute(name = "email") @Valid EmailExistVCRequest form) {
        logger.info("check member email exist");

        logger.info("email: {}", form.getEmail());
        Member member = Member.createMember(null, null, null, form.getEmail(), null);
        if (memberService.findByEmail(member).isEmpty()) {
            throw new ValidationException(EmailExistErrorCode.EMAIL_NOT_EXISTS);
        }

        return new EmailExistVCResponse(CheckMessage.EMAIL_SUCCESS);
    }

    // 아이디 찾기 시 이메일과 인증번호 존재 여부를 확인하고 아이디를 반환하는 함수이다.
    @Operation(summary = "이메일, 인증 번호 유효성 검증, 일치 여부 확인, 아이디 반환", description = "아이디 찾기 시 이메일과 인증번호 유효성 검증, 존재 여부를 확인하고 아이디를 반환합니다.")
    @ApiErrorCode(FindUserIdErrorCode.class)
    @Parameters({
            @Parameter(name = "email", description = "문자열 형태의 이메일"),
            @Parameter(name = "authNum", description = "정수 형태의 이메일 인증번호")
    })
    @GetMapping("/userid")
    public FindUserIdVCResponse findUserId(@ModelAttribute(name = "EmailChkVCRequest") @Valid FindUserIdVCRequest form) {
        logger.info("check member email, emailNumber exist");

        logger.info("email: {}, emailNumber: {}", form.getEmail(), form.getEmailNumber());
        Member member = Member.createMember(null, null, null, form.getEmail(), null);
        if (memberService.findByEmail(member).isEmpty()) {
            throw new ValidationException(FindUserIdErrorCode.EMAIL_NOT_EXISTS);
        }
        if (!mailSendService.CheckAuthNum(form.getEmail(), form.getEmailNumber())) {
            throw new ValidationException(FindUserIdErrorCode.AUTH_NUM_NOT_EXISTS);
        }
        mailSendService.deleteEmail(form.getEmail(), form.getEmailNumber());
        String userId = memberService.findUserIdByEmail(form.getEmail()).get(0);

        return new FindUserIdVCResponse(true, userId, CheckMessage.FIND_USER_ID_SUCCESS);
    }

    // 비밀번호 초기화 시 아이디와 이메일 정보의 유효성, 일치 여부를 검사하는 함수이다.
    @Operation(summary = "아이디, 이메일 유효성, 일치 여부 확인", description = "비밀번호 초기화 시 아이디, 이메일 유효성, 일치 여부를 확인하고 그 결과를 반환합니다.")
    @ApiErrorCode(IdEmailExistErrorCode.class)
    @Parameters({
            @Parameter(name = "userId", description = "문자열 형태의 유저 아이디"),
            @Parameter(name = "email", description = "문자열 형태의 이메일")
    })
    @GetMapping("/exist/id-email")
    public IdEmailExistVCResponse isValidIdEmail(@ModelAttribute(name = "IdEmailExistVCRequest") @Valid IdEmailExistVCRequest form) {
        logger.info("check member userId, email exist");

        logger.info("userId: {}, email: {}", form.getUserId(), form.getEmail());
        if (!memberService.idEmailChk(form.getUserId(), form.getEmail())) {
            throw new ValidationException(IdEmailExistErrorCode.USER_NOT_EXISTS);
        }

        return new IdEmailExistVCResponse(CheckMessage.ID_EMAIL_SUCCESS);
    }

    // 비밀번호 찾기 시 아이디, 이메일, 이메일 인증 번호의 유효성, 일치 여부를 확인하고 회원의 비밀번호를 초기화한 후 초기화된 비밀번호를 이메일로 전송하는 함수이다.
    @Operation(summary = "아이디, 이메일, 이메일 인증 번호의 유효성, 일치 여부 확인, 비밀번호 초기화", description = "아이디, 이메일, 이메일 인증 번호의 유효성, 일치 여부를 확인하고 비밀번호를 초기화한 후 그 결과를 반환합니다.")
    @ApiErrorCode(PasswordResetErrorCode.class)
    @Parameters({
            @Parameter(name = "userId", description = "문자열 형태의 유저 아이디"),
            @Parameter(name = "email", description = "문자열 형태의 이메일"),
            @Parameter(name = "emailNumber", description = "정수 형태의 이메일 인증 번호")
    })
    @PostMapping("/password")
    public PasswordResetVCResponse resetPassword(@RequestBody @Valid PasswordResetVCRequest form) {
        logger.info("check member userId, email email number exist and reset Password");

        logger.info("userId: {}, email: {}, authNum: {}", form.getUserId(), form.getEmail(), form.getEmailNumber());
        if (!memberService.idEmailChk(form.getUserId(), form.getEmail())) {
            return new PasswordResetVCResponse(false, CheckMessage.RESET_PASSWORD_FAIL);
        }
        if (!mailSendService.CheckAuthNum(form.getEmail(), form.getEmailNumber())) {
            throw new ValidationException(PasswordResetErrorCode.AUTH_NUM_NOT_EXISTS);
        }
        mailSendService.deleteEmail(form.getEmail(), form.getEmailNumber());
        memberService.findPassword(form.getUserId(), form.getEmail());

        return new PasswordResetVCResponse(true, CheckMessage.RESET_PASSWORD_SUCCESS);
    }

    @Operation(summary = "이메일로 인증 번호 전송", description = "아이디 찾기 시 중복 확인을 거친 이메일의 유효성 여부를 확인하고 그 이메일로 인증 번호를 전송합니다.")
    @ApiErrorCode(EmailCheckErrorCode.class)
    @PostMapping("/email-number")
    public EmailNumVCResponse emailNumberSend(@RequestBody @Valid EmailNumVCRequest request) {
        logger.info("이메일 인증 번호 발급 api 호출");

        Member member = Member.createMember(null, null, null, request.getEmail(), null);
        if (memberService.findByEmail(member).isEmpty()) {
            throw new ValidationException(EmailCheckErrorCode.EMAIL_NOT_EXISTS);
        }
        String authNumber = mailSendService.joinEmail(request.getEmail());

        return new EmailNumVCResponse(authNumber, MailSendValue.AUTH_NUM_DURATION, CheckMessage.AUTHENTICATION_NUM);
    }

    @Operation(summary = "이메일로 인증 번호 전송", description = "비밀번호 초기화 시 중복 확인을 거친 아이디, 이메일의 유효성 여부를 확인하고 그 이메일로 인증 번호를 전송합니다.")
    @ApiErrorCode(IdEmailExistErrorCode.class)
    @PostMapping("/id-email-number")
    public EmailNumVCResponse emailNumberSend(@RequestBody @Valid IdEmailNumVCRequest form) {
        logger.info("이메일 인증 번호 발급 api 호출");

        if (!memberService.idEmailChk(form.getUserId(), form.getEmail())) {
            throw new ValidationException(IdEmailExistErrorCode.USER_NOT_EXISTS);
        }
        String authNumber = mailSendService.joinEmail(form.getEmail());

        return new EmailNumVCResponse(authNumber, MailSendValue.AUTH_NUM_DURATION, CheckMessage.AUTHENTICATION_NUM);
    }
}
