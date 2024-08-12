package com.pathfind.system.service;

import com.pathfind.system.jwtDto.IssuedTokenCSResponse;
import io.jsonwebtoken.Jwts;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;

import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Date;

public interface JwtService {
    public IssuedTokenCSResponse createToken(String userId);

    public String getUserId(String accessToken);

    public String getSub(String token);

    public Boolean isExpired(String token);

    public String reIssueAccessToken(String refreshToken);

    public void reIssueToken(String refreshToken);
}
