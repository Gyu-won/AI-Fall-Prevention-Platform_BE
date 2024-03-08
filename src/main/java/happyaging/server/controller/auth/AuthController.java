package happyaging.server.controller.auth;

import happyaging.server.domain.user.User;
import happyaging.server.dto.auth.FindEmailDTO;
import happyaging.server.dto.auth.FindPasswordDTO;
import happyaging.server.dto.auth.JoinRequestDTO;
import happyaging.server.dto.auth.LoginRequestDTO;
import happyaging.server.dto.auth.LoginSuccessDTO;
import happyaging.server.dto.auth.ReadEmailDTO;
import happyaging.server.dto.auth.SocialLoginRequestDTO;
import happyaging.server.exception.AppException;
import happyaging.server.exception.errorcode.AppErrorCode;
import happyaging.server.service.auth.AuthService;
import happyaging.server.service.user.UserService;
import jakarta.validation.Valid;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("auth")
public class AuthController {

    private final AuthService authService;
    private final UserService userService;

    @PostMapping("/login/social")
    public ResponseEntity<?> socialLogin(
            @RequestBody @Valid SocialLoginRequestDTO socialLoginRequestDTO) {
        return authService.socialLogin(socialLoginRequestDTO);
    }

    @PostMapping("/login")
    public LoginSuccessDTO login(@RequestBody @Valid LoginRequestDTO loginRequestDTO) {
        return authService.login(loginRequestDTO.getEmail(), loginRequestDTO.getPassword());
    }

    @PostMapping("/join")
    public LoginSuccessDTO join(@RequestBody @Valid JoinRequestDTO dto) {
        if (dto.getPassword() == null) {
            throw new AppException(AppErrorCode.INVALID_JOIN);
        }
        return authService.join(dto);
    }

    @PostMapping("/join/social")
    public LoginSuccessDTO socialJoin(@RequestBody @Valid JoinRequestDTO dto) {
        return authService.join(dto);
    }

    @PostMapping("/refreshToken")
    public LoginSuccessDTO refreshToken(@RequestHeader("Authorization") String refreshToken) {
        return authService.checkRefreshToken(refreshToken.split(" ")[1]);
    }

    @PostMapping("/find/id")
    public List<ReadEmailDTO> findEmail(@RequestBody @Valid FindEmailDTO findEmailDTO) {
        return userService.findEmail(findEmailDTO.getName(), findEmailDTO.getPhoneNumber());
    }

    @PostMapping("/find/password")
    public ResponseEntity<Object> createNewPassword(@RequestBody FindPasswordDTO findPasswordDTO) {
        User user = userService.findUserByEmail(findPasswordDTO.getEmail());
        String tempPassword = userService.createNewPassword(user);
        userService.sendEmail(user.getEmail(), tempPassword);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/login/admin")
    public LoginSuccessDTO adminLogin(@RequestBody @Valid LoginRequestDTO loginRequestDTO) {
        return authService.adminLogin(loginRequestDTO.getEmail(), loginRequestDTO.getPassword());
    }
}
