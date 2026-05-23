package ru.edu.infoguard.server;

import static org.springframework.http.MediaType.APPLICATION_OCTET_STREAM;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class AntivirusBasesEndpointIntegrationTests {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void publicEndpointReturnsBinaryAntivirusBasesPackage() throws Exception {
        mockMvc.perform(get("/api/public/antivirus/bases"))
                .andExpect(status().isOk())
                .andExpect(content().contentType(APPLICATION_OCTET_STREAM))
                .andExpect(header().string("X-InfoGuard-Release-Date", "2026-05-24"))
                .andExpect(header().string("X-InfoGuard-Record-Count", "3"))
                .andExpect(result -> {
                    byte[] body = result.getResponse().getContentAsByteArray();
                    if (body.length < 64) {
                        throw new AssertionError("The antivirus bases package is unexpectedly short.");
                    }
                });
    }
}
