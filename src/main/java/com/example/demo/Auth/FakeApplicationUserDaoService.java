package com.example.demo.Auth;

import com.example.demo.security.ApplicationUserPermission;
import com.example.demo.security.ApplicationUserRole;
import com.google.common.collect.Lists;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
@Repository("fake")
public class FakeApplicationUserDaoService implements ApplicationUserDao {

    private final PasswordEncoder encoder;

    public FakeApplicationUserDaoService(PasswordEncoder encoder) {
        this.encoder = encoder;
    }

    @Override
    public Optional<ApplicationUser> selectApplicationUserByUsername(String username) {

        return getApplicationUsers()
                .stream()
                .filter(applicationUser -> username.equals(applicationUser.getUsername()))
                .findFirst();
    }

    private List<ApplicationUser> getApplicationUsers() {
        List<ApplicationUser> applicationUsers = Lists.newArrayList(
                new ApplicationUser(
                        ApplicationUserRole.STUDENT.getGrantedAuthorities(),
                        encoder.encode("anna"),
                        "AnnaSmith",
                        true,
                        true,
                        true,
                        true

                ),
                new ApplicationUser(
                        ApplicationUserRole.ADMIN.getGrantedAuthorities(),
                        encoder.encode("linda"),
                        "linda",
                        true,
                        true,
                        true,
                        true

                ),
                new ApplicationUser(
                        ApplicationUserRole.ADMINISTRATEE.getGrantedAuthorities(),
                        encoder.encode("tom"),
                        "tom",
                        true,
                        true,
                        true,
                        true

                )
        );
        return applicationUsers;
    }
}
