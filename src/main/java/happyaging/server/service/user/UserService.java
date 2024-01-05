package happyaging.server.service.user;

import happyaging.server.domain.user.User;
import happyaging.server.dto.user.UserInfoDTO;
import happyaging.server.exception.AppException;
import happyaging.server.exception.errorcode.UserErrorCode;
import happyaging.server.repository.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class UserService {
    private final UserRepository userRepository;

    @Transactional(readOnly = true)
    public UserInfoDTO findUserInfo(Long userId) {
        User user = findUserById(userId);
        return UserInfoDTO.create(user);
    }

    public Long readCurrentUserId() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.isAuthenticated()) {
            return (Long) authentication.getPrincipal();
        }
        return null;
    }

    private User findUserById(Long userId) {
        return userRepository.findById(userId)
                .orElseThrow(() -> new AppException(UserErrorCode.INVALID_USER));
    }
}
