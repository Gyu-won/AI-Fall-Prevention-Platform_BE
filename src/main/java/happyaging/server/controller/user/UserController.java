package happyaging.server.controller.user;

import happyaging.server.domain.user.User;
import happyaging.server.dto.user.UserInfoDTO;
import happyaging.server.dto.user.UserInfoUpdateDTO;
import happyaging.server.service.user.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("user")
public class UserController {

    private final UserService userService;

    @GetMapping
    public UserInfoDTO readUser() {
        Long userId = userService.readCurrentUserId();
        return userService.findUserInfo(userId);
    }

    @PutMapping
    public ResponseEntity<Object> updateUser(@RequestBody @Valid UserInfoUpdateDTO dto) {
        Long userId = userService.readCurrentUserId();
        User user = userService.findUserById(userId);
        userService.updateUserInfo(userId, user.getEmail(), dto.getName(), dto.getPhoneNumber(), dto.getPassword());
        return ResponseEntity.ok().build();
    }

    @DeleteMapping
    public ResponseEntity<Object> deleteUser() {
        Long userId = userService.readCurrentUserId();
        userService.deleteUser(userId);
        return ResponseEntity.ok().build();
    }
}
