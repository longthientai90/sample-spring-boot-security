package dangtit90.top.sample.spring.jwt.utils;

import dangtit90.top.sample.spring.jwt.domain.dto.GeneratedAccessTokenDto;
import dangtit90.top.sample.spring.jwt.domain.dto.GeneratedRefreshTokenDto;
import dangtit90.top.sample.spring.jwt.domain.dto.JWTPayloadDto;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.impl.DefaultClaims;

import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;

public class JwtTokenUtil {
    private final String USER_ID = "userId";
    private final String ROLE_NAMES = "roleNames";
    private final String LOGIN_ID = "loginId";
    private String issuer;
    private long accessTokenExpireInSecond;
    private long refreshTokenExpireInSecond;
    private int keySize;

    public JwtTokenUtil(String issuer, long accessTokenExpireInSecond, long refreshTokenExpireInSecond) {
        this.issuer = issuer;
        this.accessTokenExpireInSecond = accessTokenExpireInSecond;
        this.refreshTokenExpireInSecond = refreshTokenExpireInSecond;
        this.keySize = 2048;
    }
    public JwtTokenUtil(String issuer, long accessTokenExpireInSecond, long refreshTokenExpireInSecond, int keySize) {
        this.issuer = issuer;
        this.accessTokenExpireInSecond = accessTokenExpireInSecond;
        this.refreshTokenExpireInSecond = refreshTokenExpireInSecond;
        this.keySize = keySize;
    }

    /**
     * generated access token by asymmetric key algorithms
     * @param payloadDto
     * @param targetTime
     * @param tokenId
     * @return
     * @throws NoSuchAlgorithmException
     */
    public GeneratedAccessTokenDto generateAccessToken(JWTPayloadDto payloadDto, long targetTime, String tokenId) throws Exception {
        KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
        keyGenerator.initialize(this.keySize);

        KeyPair kp = keyGenerator.genKeyPair();
        PublicKey publicKey = kp.getPublic();
        PrivateKey privateKey = kp.getPrivate();

        GeneratedAccessTokenDto tokenDto = new GeneratedAccessTokenDto();
        long expireTime = targetTime + (accessTokenExpireInSecond * 1000);
        tokenDto.setExpireTime(expireTime);
        Date expireDate = new Date(expireTime);

        String generatedToken = Jwts.builder()
                .setIssuer(issuer)
                .setSubject(payloadDto.getLoginId())
                .setExpiration(expireDate)
                .claim(LOGIN_ID, payloadDto.getLoginId())
                .claim(USER_ID, payloadDto.getUserId())
                .claim(ROLE_NAMES, payloadDto.getRoleNames())
                .signWith(privateKey, SignatureAlgorithm.RS256).compact();
        tokenDto.setGeneratedToken(generatedToken);
        tokenDto.setGeneratedPublicKey(Base64.getEncoder().encodeToString(publicKey.getEncoded()));
        tokenDto.setGeneratedPrivateKey(Base64.getEncoder().encodeToString(privateKey.getEncoded()));
        return tokenDto;
    }

    /**
     * generated refresh token by asymmetric key algorithms
     * @param loginId
     * @param targetTime
     * @param privKeyStr
     * @return
     * @throws Exception
     */
    public GeneratedRefreshTokenDto generateRefreshToken(String loginId, long targetTime, String privKeyStr) throws Exception {
        PrivateKey privateKey = getPrivateKeyFromString(privKeyStr);
        GeneratedRefreshTokenDto tokenDto = new GeneratedRefreshTokenDto();
        long expireTime = targetTime + (refreshTokenExpireInSecond * 1000);
        tokenDto.setExpireTime(expireTime);
        Date expireDate = new Date(expireTime);

        String refreshToken = Jwts.builder()
                .setIssuer(issuer)
                .setSubject(loginId)
                .setExpiration(expireDate)
                .signWith(privateKey, SignatureAlgorithm.RS256).compact();
        tokenDto.setGeneratedToken(refreshToken);
        return tokenDto;
    }

    public PrivateKey getPrivateKeyFromString(String privKeyStr) throws Exception {
        byte[] sigBytes = Base64.getDecoder().decode(privKeyStr.getBytes("UTF-8"));
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(sigBytes);
        KeyFactory keyFact = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFact.generatePrivate(privateKeySpec);
        return privateKey;
    }

    public PublicKey getPublicKeyFromString(String pubKeyStr) throws Exception {
        byte[] encodedPublicKey = Base64.getDecoder().decode(pubKeyStr);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(encodedPublicKey);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
    }

    public JWTPayloadDto getPayloadFromJWT(String token, String pubKeyStr) throws Exception {
        PublicKey publicKey = getPublicKeyFromString(pubKeyStr);
        Jws parseClaims = Jwts.parserBuilder().setSigningKey(publicKey).build().parseClaimsJws(token);
        JWTPayloadDto payloadDto = new JWTPayloadDto();
        DefaultClaims body = (DefaultClaims) parseClaims.getBody();
        payloadDto.setLoginId((String) body.get(LOGIN_ID));
        payloadDto.setUserId(((Integer) body.get(USER_ID)).longValue());
        payloadDto.setRoleNames((ArrayList<String>) body.get(ROLE_NAMES));
        return payloadDto;
    }
}
