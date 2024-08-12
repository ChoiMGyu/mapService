/*
 * 클래스 기능 : 회원 관련 페이지 렌더링을 하는 controller
 * 최근 수정 일자 : 2024.08.08(목)
 */
package com.pathfind.system.controller;

import com.pathfind.system.domain.Check;
import com.pathfind.system.domain.Member;
import com.pathfind.system.memberDto.*;
import com.pathfind.system.service.MailSendService;
import com.pathfind.system.service.MemberService;
import com.pathfind.system.validation.ValidationSequence;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Controller
@RequiredArgsConstructor
@RequestMapping("/members/*")
public class MemberController {

    private static final Logger logger = LoggerFactory.getLogger(MemberController.class);

    private final MemberService memberService;

    private final MailSendService mailSendService;

    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    // 컨트롤러를 호출한 URI의 파일 경로만 추출해 반환하는 함수이다.
    private String getPath(HttpServletRequest request) {
        String path = null;
        try {
            path = new URI(request.getHeader("REFERER")).getPath();
            logger.info("getPath: {}", path);
        } catch (URISyntaxException e) {
            logger.info("URISyntaxException: {}", e.getMessage());
        }
        return path;
    }

    // submitForm을 model에 추가하는 함수이다.
    private void addSubmitForm(Model model, HttpSession session) {
        SubmitForm submitForm = (SubmitForm) session.getAttribute(SessionConst.SUBMIT_MEMBER);
        if (submitForm == null) {
            session.setAttribute(SessionConst.SUBMIT_MEMBER, new SubmitForm());
            model.addAttribute("submitForm", new SubmitForm());
        } else {
            model.addAttribute("submitForm", submitForm);
        }
    }

    // 이메일 인증번호의 유효성, 동일한지 여부를 검사하는 함수이다.
    private void emailNumberValidation(SubmitForm form, BindingResult result) {
        if (!form.isEmailNumberSend()) {
            result.rejectValue("emailNumber", "Empty.emailNumber.send");
        }
        if (!result.hasFieldErrors("emailNumber") && Objects.equals(form.getEmailNumber(), "")) {
            result.rejectValue("emailNumber", "Empty.emailNumber");
        }

        String patternEmailNumber = "^[0-9]*$";
        logger.info("emailNumber: {}", form.getEmailNumber());
        boolean regexEmailNumber = Pattern.matches(patternEmailNumber, form.getEmailNumber());
        if (!result.hasFieldErrors("emailNumber") && !regexEmailNumber) {
            result.rejectValue("emailNumber", "Format.emailNumber");
        }

        boolean isSame = mailSendService.CheckAuthNum(form.getEmail(), form.getEmailNumber());
        if (!result.hasFieldErrors("emailNumber") && !isSame) {
            result.rejectValue("emailNumber", "NotSame.emailNumber");
        }
    }

    // 약관 동의 페이지를 반환하는 함수이다.
    @GetMapping(value = "/agree")
    public String getAgree() {
        logger.info("get register agree");

        return "members/agree";
    }

    // 회원 가입 양식 페이지를 반환하는 함수이다.
    @GetMapping(value = "/new")
    public String getRegister() {
        logger.info("get register form");

        return "members/registerForm";
    }

    // 회원 가입 완료 페이지를 반환하는 함수이다.
    @GetMapping("/registerComplete")
    public String registerComplete() {
        logger.info("회원 가입이 성공적으로 완료되었습니다.");

        return "members/registerComplete";
    }

    // 아이디 찾기 페이지를 반환하는 함수이다.
    @GetMapping("/findUserId")
    public String findUserId() {
        logger.info("find userId");

        return "members/findUserId";
    }

    // 사용자에게 아이디를 포함한 페이지를 반환하는 함수이다.
    @GetMapping("/returnId")
    public String returnId(@RequestParam(name = "userId") String userId, Model model) {
        logger.info("your user id: {}", userId);

        model.addAttribute("userId", userId);

        return "members/yourUserId";
    }

    // 비밀번호 초기화 페이지를 반환하는 함수이다.
    @GetMapping("/findPassword")
    public String findPassword() {
        logger.info("find password");

        return "members/findPassword";
    }

    // 비밀번호 초기화 성공 시 사용자에게 보여지는 페이지를 반환하는 함수이다.
    @GetMapping("/yourPassword")
    public String resetPasswordResult() {
        return "members/yourPassword";
    }

    @GetMapping("/updatePassword")
    public String updatePasswordForm(Model model) {
        logger.info("get updatePasswordForm");
        model.addAttribute("passwordForm", new PasswordForm());
        return "members/updatePasswordForm";
    }

    @PostMapping("/updatePassword")
    public String updatePassword(@Validated(ValidationSequence.class) PasswordForm form, BindingResult result, Model model, HttpSession session, RedirectAttributes rttr) {
        if (result.hasErrors()) {
            return "members/updatePasswordForm";
        }

        //검증할 패스워드 정규식 패턴
        String regex = "(?=.*[0-9])(?=.*[a-zA-Z])(?=.*\\W)(?=\\S+$).{8,20}";
        Pattern pattern = Pattern.compile(regex);

        List<Member> memberList = memberService.findByUserId(((Member) session.getAttribute(SessionConst.LOGIN_MEMBER)));

        if (memberList.isEmpty()) {
            return "redirect:/";
        }
        Member loginMember = memberList.get(0);
        logger.info("로그인 멤버의 아이디 : " + loginMember.getId() + ", 패스워드 : " + loginMember.getPassword());

        Matcher matcher = pattern.matcher(form.getNewPassword1());

        logger.info("old password: {}, encoded password: {}", form.getOldPassword(), loginMember.getPassword());
        if (!bCryptPasswordEncoder.matches(form.getOldPassword(), loginMember.getPassword())) {
            logger.info("이전 패스워드가 일치하지 않는 경우");
            result.rejectValue("oldPassword", "NotSame.newPassword1");
        }
        if (!form.getNewPassword1().equals(form.getNewPassword2())) {
            logger.info("새 패스워드와 새 패스워드 확인이 일치하지 않는 경우");
            result.rejectValue("newPassword2", "NotSame.newPassword2");
        }
        if (!matcher.matches()) {
            logger.info("새 패스워드 형식이 올바르지 않은 경우");
            result.rejectValue("newPassword2", "Format.newPassword2");
        }

        if (!result.hasErrors()) {
            logger.info("패스워드를 정상적으로 변경했습니다.");
            //logger.info("controller에서 비밀번호 변경을 하기 전 loginMember 객체 : " + loginMember);
            //비밀번호 변경을 하기 전 loginMember와 서비스 계층 로직 내에서 비밀번호 변경을 한 loginMember는 동일함
            loginMember = memberService.updatePassword(loginMember.getId(), form.getOldPassword(), form.getNewPassword1(), form.getNewPassword2());
            //그러나 비밀번호 변경을 한 후 반환된 loginMember는 이전의 loginMember와는 다른 객체임
            //logger.info("controller에서 비밀번호 변경을 한 후 loginMember : " + loginMember);
            session.setAttribute(SessionConst.LOGIN_MEMBER, loginMember);
            rttr.addFlashAttribute("message", "패스워드를 변경했습니다.");
            return "redirect:/members/updatePassword";
        }

        return "members/updatePasswordForm";
    }

    @GetMapping("/loginForm")
    public String loginForm(@RequestParam(value = "error", required = false) String errorMessage, @ModelAttribute LoginForm form, BindingResult result) {
        logger.info("get loginForm");
        if (errorMessage != null) {
            logger.info("Error message: {}", errorMessage);
            result.reject("loginFail", errorMessage);
        }
        return "members/loginForm";
    }

    @GetMapping("/recover")
    public String recoverUserForm(Model model, HttpSession session) {
        logger.info("get recoverUserForm");

        Member loginMember = (Member) session.getAttribute(SessionConst.LOGIN_MEMBER);
        //model.addAttribute("recoverForm", new RecoverForm());
        model.addAttribute("userId", loginMember.getUserId());
        logger.info("loginMember userId : " + loginMember.getUserId());

        return "members/recoverUserForm";
    }

    @PostMapping("/recover")
    public String recoverUser(HttpSession session, RedirectAttributes rttr) {
        logger.info("post recoverUser");

        Member loginMember = (Member) session.getAttribute(SessionConst.LOGIN_MEMBER);
        memberService.recoverMember(loginMember.getId());
        session.invalidate();
        rttr.addFlashAttribute("message", "휴면 상태를 해제하였습니다.");
        return "redirect:/";
    }

    // 나의 프로필 페이지를 반환하는 함수이다.
    @GetMapping("/myProfile")
    public String getProfile(HttpServletRequest request, Model model) {
        HttpSession session = request.getSession(false);
        if (session == null) {
            return "redirect:/members/loginForm";
        }

        Member member = (Member) session.getAttribute(SessionConst.LOGIN_MEMBER);
        session.setAttribute(SessionConst.SUBMIT_MEMBER, null);
        MemberForm memberForm = new MemberForm();
        memberForm.setUserId(member.getUserId());
        memberForm.setEmail(member.getEmail());
        NicknameForm nicknameForm = new NicknameForm();
        nicknameForm.setNickname(member.getNickname());

        model.addAttribute("memberForm", memberForm);
        model.addAttribute("nicknameForm", nicknameForm);

        return "members/myProfile";
    }

    // 나의 프로필 페이지에서 닉네임을 변경할 수 있게 하는 함수이다.
    @PostMapping("/updateNickname")
    public String updateNickname(MemberForm memberForm, @Valid NicknameForm nicknameForm, BindingResult result, HttpServletRequest request, RedirectAttributes rttr) {
        HttpSession session = request.getSession(false);
        if (session == null) {
            return "redirect:/members/loginForm";
        }

        Member member = (Member) session.getAttribute(SessionConst.LOGIN_MEMBER);
        memberForm.setUserId(member.getUserId());
        memberForm.setEmail(member.getEmail());

        String patternNickname = "^[ㄱ-ㅎ가-힣a-zA-Z0-9-_\\s]{2,12}$";
        boolean regexNickname = Pattern.matches(patternNickname, nicknameForm.getNickname());
        if (!result.hasFieldErrors("nickname") && !regexNickname) {
            result.rejectValue("nickname", "Format.nickname");
        }

        Member findMember = Member.createMember(null, null, nicknameForm.getNickname(), null, null);
        if (nicknameForm.getNickname() != null && !memberService.findByNickname(findMember).isEmpty()) {
            result.rejectValue("nickname", "Nickname.exist");
        }

        if (result.hasErrors()) {
            return "members/myProfile";
        }

        Optional<Member> newMember = memberService.updateNickname(member.getId(), nicknameForm.getNickname());
/*        logger.info("newMember: {}", newMember.get());
        logger.info("newMember - isDormant: {}", newMember.get().getCheck().isDormant());
        logger.info("newMember: {}", newMember.get());*/
        if (newMember.isEmpty()) {
            result.rejectValue("nickname", "Nickname.exist");
            return "members/myProfile";
        }

        session.setAttribute(SessionConst.LOGIN_MEMBER, newMember.get());
        rttr.addFlashAttribute("message", "닉네임을 변경했습니다.");

        return "redirect:/members/myProfile";
    }

    // 이메일 변경 페이지를 반환하는 함수이다.
    @GetMapping("/updateEmail")
    public String updateEmail(HttpServletRequest request, Model model) {
        logger.info("member update email");

        HttpSession session = request.getSession(false);
        if (session == null) {
            return "redirect:/members/loginForm";
        }

        addSubmitForm(model, session);

        return "members/updateEmail";
    }

    // 이메일의 유효성, 중복 여부를 검사하고 사용자의 이메일 변경을 수행하는 함수이다.
    @PostMapping("/updateEmail")
    public String updateEmail(SubmitForm form, BindingResult result, HttpServletRequest request, RedirectAttributes rttr) {
        HttpSession session = request.getSession(false);
        if (session == null) {
            return "redirect:/members/loginForm";
        }

        emailNumberValidation(form, result);

        String path = getPath(request);

        if (result.hasErrors()) {
            form.setEmailNumberCheck(false);
            session.setAttribute(SessionConst.SUBMIT_MEMBER, form);
            rttr.addFlashAttribute(BindingResult.MODEL_KEY_PREFIX + "submitForm", result);
            return "redirect:" + path;
        }

        Member member = (Member) session.getAttribute(SessionConst.LOGIN_MEMBER);
        member = memberService.updateEmail(member.getId(), form.getEmail());
        rttr.addFlashAttribute("message", "이메일을 변경했습니다.");
        session.setAttribute(SessionConst.LOGIN_MEMBER, member);
        session.setAttribute(SessionConst.SUBMIT_MEMBER, null);

        return "redirect:/members/myProfile";
    }

    // 탈퇴 안내 페이지를 반환하는 함수이다.
    @GetMapping("/leave")
    public String leaveNotice(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session == null) {
            return "redirect:/members/loginForm";
        }

        return "members/leaveNotice";
    }

    // 사용자의 회원 탈퇴를 수행하고 탈퇴 완료 페이지를 반환하는 함수이다.
    @PostMapping("/leave")
    public String leaveService(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session == null) {
            return "redirect:/members/loginForm";
        }

        Member member = (Member) session.getAttribute(SessionConst.LOGIN_MEMBER);
        memberService.deleteMember(member.getId());
        session.invalidate();

        return "members/bye";
    }
}
