package happyaging.server.service.user;

import happyaging.server.domain.user.User;
import happyaging.server.dto.auth.ReadEmailDTO;
import happyaging.server.dto.user.UserInfoDTO;
import happyaging.server.exception.AppException;
import happyaging.server.exception.errorcode.AppErrorCode;
import happyaging.server.repository.user.UserRepository;
import happyaging.server.util.Encoder;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import java.security.SecureRandom;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.scheduling.annotation.Async;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class UserService {

    private static final int TEMP_PASSWORD_LENGTH = 8;
    private final JavaMailSender emailSender;
    private final UserRepository userRepository;

    @PersistenceContext
    private EntityManager entityManager;

    @Transactional(readOnly = true)
    public UserInfoDTO findUserInfo(Long userId) {
        User user = findUserById(userId);
        return UserInfoDTO.create(user);
    }

    @Transactional
    public void updateUserInfo(Long userId, String email, String name, String phoneNumber, String password) {
        User user = findUserById(userId);
        user.update(email, name, phoneNumber, Encoder.encode(password, user.getVendor()));
    }

    @Transactional
    public void deleteUser(Long id) {
        User user = findUserById(id);
        user.delete();
    }

    @Transactional(readOnly = true)
    public Long readCurrentUserId() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.isAuthenticated()) {
            return (Long) authentication.getPrincipal();
        }
        return null;
    }

    @Transactional(readOnly = true)
    public User authenticate(Long userId) {
        return findUserById(userId);
    }

    @Transactional(readOnly = true)
    public List<ReadEmailDTO> findEmail(String name, String phoneNumber) {
        List<User> users = userRepository.findAllByNameAndPhoneNumber(name, phoneNumber);
        if (users.isEmpty()) {
            throw new AppException(AppErrorCode.INVALID_ACCOUNT);
        }
        return users.stream()
                .map(ReadEmailDTO::create)
                .toList();
    }

    @Transactional(readOnly = true)
    public User findUserByEmail(String email) {
        return userRepository.findByEmail(email)
                .orElseThrow(() -> new AppException(AppErrorCode.INVALID_ACCOUNT));
    }

    @Transactional
    public String createNewPassword(User user) {
        String temporaryPassword = generateRandomPassword();
        String encodedPassword = Encoder.encode(temporaryPassword, user.getVendor());
        user.update(user.getEmail(), user.getName(), user.getPhoneNumber(), encodedPassword);
        return temporaryPassword;
    }

    @Transactional(readOnly = true)
    public User findUserById(Long userId) {
        return userRepository.findById(userId)
                .orElseThrow(() -> new AppException(AppErrorCode.INVALID_USER));
    }

    private String generateRandomPassword() {
        SecureRandom random = new SecureRandom();
        String characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        StringBuilder password = new StringBuilder(TEMP_PASSWORD_LENGTH);
        for (int i = 0; i < TEMP_PASSWORD_LENGTH; i++) {
            password.append(characters.charAt(random.nextInt(characters.length())));
        }
        return password.toString();
    }


    @Async
    public void sendEmail(String to, String temporaryPassword) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(to);
        message.setSubject("[해피에이징] 비밀번호 재발급 안내");
        message.setText(
                "새로 생성된 비밀번호 입니다: " + temporaryPassword + "\n\n해당 비밀번호로 로그인 후 반드시 비밀번호를 변경해 주시기 바랍니다.");
        emailSender.send(message);
    }
}
