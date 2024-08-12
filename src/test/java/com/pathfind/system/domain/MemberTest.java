package com.pathfind.system.domain;

import org.junit.Assert;
import org.junit.Test;

import static org.junit.jupiter.api.Assertions.*;

public class MemberTest {
    @Test
    public void 임의_비밀번호_생성_AND_변경() throws Exception {
        //given
        Member member = Member.createMember("userID1", "1234", "userA", "hello@hello.net", null);
        String originalPassword = member.getPassword();

        //when
        member.updateToTemporaryPassword();

        //then
        Assert.assertNotEquals(originalPassword, member.getPassword());
        System.out.println("Original password: " + originalPassword);
        System.out.println("Updated temporary password: " + member.getPassword());
    }

}