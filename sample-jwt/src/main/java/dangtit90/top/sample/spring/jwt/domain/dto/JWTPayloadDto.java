package dangtit90.top.sample.spring.jwt.domain.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class JWTPayloadDto {
    private long userId;
    private String loginId;
    private List<String> roleNames;
}
