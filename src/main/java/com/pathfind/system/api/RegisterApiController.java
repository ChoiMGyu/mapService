/*
 * 클래스 기능 : 회원 가입 API Controller
 * 최근 수정 일자 : 2024.08.04(일)
 */
package com.pathfind.system.api;

import com.pathfind.system.customAnnotation.ApiErrorCode;
import com.pathfind.system.domain.Check;
import com.pathfind.system.domain.Member;
import com.pathfind.system.exception.*;
import com.pathfind.system.memberDto.EmailChkVCRequest;
import com.pathfind.system.memberDto.EmailChkVCResponse;
import com.pathfind.system.memberDto.EmailNumVCRequest;
import com.pathfind.system.memberDto.EmailNumVCResponse;
import com.pathfind.system.service.MailSendService;
import com.pathfind.system.exception.EmailCheckErrorCode;
import com.pathfind.system.exception.NicknameCheckErrorCode;
import com.pathfind.system.exception.UserIdCheckErrorCode;
import com.pathfind.system.exception.ValidationException;
import com.pathfind.system.memberDto.*;
import com.pathfind.system.service.MailSendValue;
import com.pathfind.system.service.MemberService;
import com.pathfind.system.service.RedisUtil;
import com.pathfind.system.validation.ValidationSequence;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.validation.BindingResult;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.util.concurrent.TimeUnit;

@Tag(name = "회원 가입 API", description = "회원 가입 시 사용되는 API")
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/registration/*")
public class RegisterApiController {

    private static final Logger logger = LoggerFactory.getLogger(RegisterApiController.class);

    private final MemberService memberService;

    private final MailSendService mailSendService;

    private final RedisUtil redisUtil;

    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    @Autowired
    private RedisTemplate<String, String> redisTemplate;

    // 아이디 유효성, 중복 확인 여부를 검사하는 함수이다.
    @Operation(summary = "유저 아이디 유효성 검증, 중복 여부 확인", description = "회원 가입 시 유저 아이디 유효성, 중복 여부를 확인하고 그 결과를 반환합니다.")
    @ApiErrorCode(UserIdCheckErrorCode.class)
    @GetMapping("check/user-id")
    public UserIdCheckVCResponse userIdChk(@Parameter(name = "userId", description = "문자열 형태의 유저 아이디") @ModelAttribute(name = "userId") @Validated(ValidationSequence.class) UserIdCheckVCRequest form) {
        logger.info("member user id check");

        logger.info("{}", form.getUserId());
        Member member = Member.createMember(form.getUserId(), null, null, null, null);
        if (!memberService.findByUserId(member).isEmpty()) {
            throw new ValidationException(UserIdCheckErrorCode.ID_ALREADY_EXISTS);
        }

        return new UserIdCheckVCResponse(true, CheckMessage.USER_ID);
    }

    // 닉네임 유효성, 중복 확인 여부를 검사하는 함수이다.
    @Operation(summary = "닉네임 유효성 검증, 중복 여부 확인", description = "회원 가입 시 닉네임 유효성, 중복 여부를 확인하고 그 결과를 반환합니다.")
    @ApiErrorCode(NicknameCheckErrorCode.class)
    @GetMapping("check/nickname")
    public NicknameCheckVCResponse nicknameChk(@Parameter(name = "nickname", description = "문자열 형태의 닉네임") @ModelAttribute(name = "nickname") @Validated(ValidationSequence.class) NicknameVCRequest form) {
        logger.info("member nickname check");

        logger.info("{}", form.getNickname());
        Member member = Member.createMember(null, null, form.getNickname(), null, null);
        if (!memberService.findByNickname(member).isEmpty()) {
            throw new ValidationException(NicknameCheckErrorCode.NICKNAME_ALREADY_EXISTS);
        }

        return new NicknameCheckVCResponse(true, CheckMessage.NICKNAME);
    }

    // 이메일 유효성, 중복 확인 여부를 검사하는 함수이다.
    @Operation(summary = "이메일 유효성 검증, 중복 여부 확인", description = "회원 가입 시 이메일 유효성, 중복 여부를 확인하고 그 결과를 반환합니다.")
    @ApiErrorCode(EmailCheckErrorCode.class)
    @GetMapping("check/email")
    public EmailCheckVCResponse emailChk(@Parameter(name = "email", description = "문자열 형태의 이메일") @ModelAttribute(name = "email") @Validated(ValidationSequence.class) EmailCheckVCRequest form) {
        logger.info("member email check");

        logger.info("{}", form.getEmail());
        Member member = Member.createMember(null, null, null, form.getEmail(), null);
        if (!memberService.findByEmail(member).isEmpty()) {
            throw new ValidationException(EmailCheckErrorCode.EMAIL_ALREADY_EXISTS);
        }

        return new EmailCheckVCResponse(true, CheckMessage.EMAIL);
    }

    @Operation(summary = "이메일로 인증 번호 전송", description = "회원 가입 시 중복 확인을 거친 이메일의 유효성 여부를 확인하고 그 이메일로 인증 번호를 전송합니다.")
    @ApiErrorCode(EmailCheckErrorCode.class)
    @PostMapping("emailNumberSend")
    public EmailNumVCResponse emailNumberSend(@RequestBody @Validated(ValidationSequence.class) EmailNumVCRequest request) {
        logger.info("이메일 인증 번호 발급 api 호출");

        Member member = Member.createMember(null, null, null, request.getEmail(), null);
        if (!memberService.findByEmail(member).isEmpty()) {
            throw new ValidationException(EmailCheckErrorCode.EMAIL_ALREADY_EXISTS);
        }
        String authNumber = mailSendService.joinEmail(request.getEmail());

        return new EmailNumVCResponse(authNumber, MailSendValue.AUTH_NUM_DURATION, CheckMessage.AUTHENTICATION_NUM);
    }

    @Operation(summary = "인증 번호 동일성 여부 검사", description = "회원 가입 시 이메일로 전송된 인증 번호와 입력한 인증 번호가 동일한지 확인하고 그 결과를 반환합니다.")
    @ApiErrorCode(AuthenticationChkErrorCode.class)
    @PostMapping("emailNumberChk")
    public EmailChkVCResponse emailNumberChk(@RequestBody @Validated(ValidationSequence.class) EmailChkVCRequest request) {
        logger.info("이메일 인증 번호를 확인 api 호출");
        Long expireDuration = redisTemplate.getExpire(request.getEmail(), TimeUnit.SECONDS);
        if(expireDuration == null || expireDuration <= 0) {
            //인증 번호 유효 시간이 초과되었음
            throw new ValidationException(AuthenticationChkErrorCode.TIME_OUT);
        }
        boolean chk = mailSendService.CheckAuthNum(request.getEmail(), request.getAuthNum());
        if(!chk) {
            if(redisUtil.getData(request.getEmail()) == null) {
                //인증 번호 확인 후 인증 번호를 수정하고 발급받지 않고 확인하고자 할 때
                throw new ValidationException(AuthenticationChkErrorCode.CHANGE_AUTHNUM);
            }
//            if(!redisUtil.getData(request.getEmail()).equals(request.getAuthNum())) {
//                //인증 번호 확인 후 이메일을 수정하였는데 인증 번호 재발급을 받지 않고 인증 번호를 확인하고자 할 때
//                throw new ValidationException(AuthenticationChkErrorCode.CHANGE_EMAIL);
//            }
            //이메일 인증 번호 발급을 받은 후 입력된 인증 번호가 동일 여부 판단
            else throw new ValidationException(AuthenticationChkErrorCode.NOT_SAME);
        }
        return new EmailChkVCResponse(chk, CheckMessage.AUTHENTICATION_CHK);
    }

    @Operation(summary = "패스워드 동일 여부 검사", description = "회원 가입 시 입력된 패스워드와 패스워드 확인이 동일한지 확인하고 그 결과를 반환합니다.")
    @ApiErrorCode(PasswordCheckError.class)
    @PostMapping("check/password")
    public PasswordVCResponse passwordChk(@RequestBody @Validated(ValidationSequence.class) PasswordVCRequest request) {
        logger.info("패스워드 api 호출");
        //공통 경우
        /*
            1. 패스워드 입력란이 비었는 경우 (NOT_EMPTY)
            2. 패스워드가 형식을 만족하지 못하는 경우 (PATTERN)
         */
        //패스워드 확인이 있는 경우
        /*
            1. 패스워드 확인이 패스워드와 일치하지 않는 경우
         */
        boolean chk = request.getPasswordConfirm().isEmpty();
        if(chk) {
            throw new ValidationException(PasswordCheckError.PASSWORD_CONFIRM_EMPTY);
        }
        else {
            if (!request.getPassword().equals(request.getPasswordConfirm())) {
                throw new ValidationException(PasswordCheckError.NOT_SAME);
            }
        }

        return new PasswordVCResponse(true, CheckMessage.PASSWORD);
    }

    @Operation(summary = "회원 가입", description = "회원 가입을 진행하고 성공 또는 실패 여부를 반환합니다.")
    @PostMapping("register")
    public RegisterVCResponse register(@RequestBody @Valid RegisterVCRequest request, BindingResult bindingResult) {
        logger.info("회원가입 api 호출");

        if(bindingResult.hasErrors()) {
            return new RegisterVCResponse(false, CheckMessage.REGISTER_FAIL);
        }

        Member member = Member.createMember(null, null, null, null, null);

        //아이디
        //에러1. 아이디 입력란이 비어있을 때
        member.changeUserId(request.getUserId());
        //에러2. 아이디 패턴을 만족하지 못하였을 때
        //에러3. 아이디 중복 확인을 통과하지 못하였을 때
        if (!memberService.findByUserId(member).isEmpty()) {
            return new RegisterVCResponse(false, CheckMessage.REGISTER_FAIL);
        }

        //닉네임
        //에러1. 닉네임 입력란이 비어있을 때
        member.changeNickname(request.getNickname());
        //에러2. 닉네임 패턴을 만족하지 못하였을 때
        //에러3. 닉네임 중복 확인을 통과하지 못하였을 때
        if (!memberService.findByNickname(member).isEmpty()) {
            return new RegisterVCResponse(false, CheckMessage.REGISTER_FAIL);
        }

        //이메일
        //에러1. 이메일 입력란이 비어있을 때
        member.changeEmail(request.getEmail());
        //에러2. 이메일 패턴을 만족하지 못하였을 때
        //에러3. 이메일 중복 확인을 통과하지 못하였을 때
        //에러4. 인증 번호가 발급되지 않았을 때
        //에러5. 인증 번호 입력란이 비었을 때
        //에러6. 인증 번호가 일치하지 않을 때
        //에러7. 인증 번호 유효 시간이 초과되었을 때
        //에러8. 인증 번호를 올바르게 입력하였으나 인증 번호 확인 버튼을 누르지 않은 경우
        if(!mailSendService.deleteEmail(request.getEmail(), request.getAuthNum())) {
            //인증 번호 확인을 마친 후 이메일을 수정하였는 경우 회원 가입 불가능 하게 만들기
            return new RegisterVCResponse(false, CheckMessage.REGISTER_FAIL);
        }


        //비밀번호
        //에러1. 비밀번호 입력란이 비어있을 때
        //에러2. 비밀번호 확인란이 비어있을 때
        member.changePassword(request.getPassword());
        //에러3. 비밀번호 패턴을 만족하지 못하였을 때
        //에러4. 비밀번호와 비밀번호 확인이 동일하지 않을 때
        if(!member.checkPassword(request.getPasswordConfirm())) {
            return new RegisterVCResponse(false, CheckMessage.REGISTER_FAIL);
        }

        Check check = Check.createCheck();
        check.changeEmailAuth(true);
        check.changeInformationAgree(true);
        member.changePassword(bCryptPasswordEncoder.encode(request.getPassword()));
        member.changeCheck(check);
        memberService.register(member);

        return new RegisterVCResponse(true, CheckMessage.REGISTER_SUCCESS);
    }
}
