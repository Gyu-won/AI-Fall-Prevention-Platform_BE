package happyaging.server.dto.auth;

import happyaging.server.domain.user.Vendor;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor
public abstract class JoinRequestDTO {
    @NotEmpty(message = "이름은 필수입니다.")
    private String name;

    @NotEmpty(message = "이메일은 필수입니다.")
    private String email;
    
    private String password;

    @NotEmpty(message = "전화번호는 필수입니다.")
    private String phoneNumber;

    @NotNull(message = "vendor는 필수입니다.")
    private Vendor vendor;
}
