package dangtit90.top.sample.spring.jwt.domain.dto;

import lombok.Data;

@Data
public class GeneratedRefreshTokenDto {
    private String generatedToken;
    private long expireTime;
}
