package com.pathfind.system.entity;

import com.pathfind.system.service.RedisUtil;
import org.assertj.core.api.Assertions;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.transaction.annotation.Transactional;

@RunWith(SpringRunner.class)
@SpringBootTest
@Transactional
public class RedisTest {

    @Autowired
    private RedisUtil redisUtil;

    @Test
    public void redisTest() throws Exception
    {
        //given
        String email = "test@test.com";
        String code = "aaa111";

        //when
        redisUtil.setDataExpire(email, code, 60 * 60L);

        //then
        Assertions.assertThat(redisUtil.getData(email)).isEqualTo("aaa111");
    }
}
