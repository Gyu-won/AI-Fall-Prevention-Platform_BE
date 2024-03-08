package happyaging.server.util;

import happyaging.server.domain.user.Vendor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

public class Encoder {

    private static PasswordEncoder encoder = new BCryptPasswordEncoder();

    public static String encode(String password, Vendor vendor) {
        if (vendor == Vendor.HAPPY_AGING) {
            return encoder.encode(password);
        }
        return password;
    }
}
