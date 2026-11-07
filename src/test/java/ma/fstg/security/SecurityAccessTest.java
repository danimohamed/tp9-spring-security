package ma.fstg.security;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.unauthenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrlPattern;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class SecurityAccessTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Test
    void homePageIsPublic() throws Exception {
        mockMvc.perform(get("/"))
                .andExpect(status().isOk())
                .andExpect(content().string(org.hamcrest.Matchers.containsString("application publique")));
    }

    @Test
    void anonymousUserIsRedirectedToLoginForUserDashboard() throws Exception {
        mockMvc.perform(get("/user/dashboard"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrlPattern("**/login"));
    }

    @Test
    void anonymousUserIsRedirectedToLoginForAdminDashboard() throws Exception {
        mockMvc.perform(get("/admin/dashboard"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrlPattern("**/login"));
    }

    @Test
    void userCanAccessUserDashboard() throws Exception {
        mockMvc.perform(get("/user/dashboard").with(user("user").roles("USER")))
                .andExpect(status().isOk())
                .andExpect(content().string(org.hamcrest.Matchers.containsString("Espace Utilisateur")));
    }

    @Test
    void userIsForbiddenFromAdminDashboard() throws Exception {
        mockMvc.perform(get("/admin/dashboard").with(user("user").roles("USER")))
                .andExpect(status().isForbidden());
    }

    @Test
    void adminCanAccessBothDashboards() throws Exception {
        mockMvc.perform(get("/user/dashboard").with(user("admin").roles("ADMIN", "USER")))
                .andExpect(status().isOk());
        mockMvc.perform(get("/admin/dashboard").with(user("admin").roles("ADMIN", "USER")))
                .andExpect(status().isOk())
                .andExpect(content().string(org.hamcrest.Matchers.containsString("Espace Administrateur")));
    }

    @Test
    void loginWithValidUserCredentialsSucceeds() throws Exception {
        mockMvc.perform(formLogin("/login").user("user").password("1111"))
                .andExpect(authenticated().withUsername("user"));
    }

    @Test
    void loginWithValidAdminCredentialsSucceeds() throws Exception {
        mockMvc.perform(formLogin("/login").user("admin").password("1234"))
                .andExpect(authenticated().withUsername("admin"));
    }

    @Test
    void loginWithWrongPasswordFails() throws Exception {
        mockMvc.perform(formLogin("/login").user("user").password("wrong"))
                .andExpect(unauthenticated());
    }

    @Test
    void passwordsAreStoredAsBcryptHashes() {
        String hash = passwordEncoder.encode("1111");
        assertThat(hash).startsWith("$2a$");
        assertThat(passwordEncoder.matches("1111", hash)).isTrue();
        assertThat(passwordEncoder.matches("1234", hash)).isFalse();
    }

    @Test
    void logoutRedirectsToLoginPage() throws Exception {
        mockMvc.perform(post("/logout").with(user("user").roles("USER")).with(csrf()))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/login?logout"));
    }
}
