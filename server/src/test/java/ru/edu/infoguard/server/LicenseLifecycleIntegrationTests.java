package ru.edu.infoguard.server;

import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class LicenseLifecycleIntegrationTests {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Test
    void userCanActivateCurrentLicenseAndAdminCanRenewIt() throws Exception {
        final String adminToken = login("admin", "Admin23358!");

        mockMvc.perform(post("/api/admin/users")
                        .contentType(APPLICATION_JSON)
                        .header("Authorization", "Bearer " + adminToken)
                        .content("""
                                {
                                  "username": "student2",
                                  "password": "Student23358!",
                                  "fullName": "Student Two",
                                  "role": "USER"
                                }
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("student2"));

        final String userToken = login("student2", "Student23358!");

        final MvcResult myLicensesResult = mockMvc.perform(get("/api/licenses/me")
                        .header("Authorization", "Bearer " + userToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].active").value(false))
                .andReturn();

        final JsonNode licenses = objectMapper.readTree(myLicensesResult.getResponse().getContentAsString());
        final long licenseId = licenses.get(0).get("id").asLong();
        final String licenseKey = licenses.get(0).get("licenseKey").asText();

        mockMvc.perform(get("/api/licenses/current")
                        .header("Authorization", "Bearer " + userToken)
                        .param("deviceId", "DEV-23358"))
                .andExpect(status().isNotFound());

        mockMvc.perform(post("/api/licenses/activate")
                        .contentType(APPLICATION_JSON)
                        .header("Authorization", "Bearer " + userToken)
                        .content("""
                                {
                                  "licenseKey": "%s",
                                  "deviceId": "DEV-23358"
                                }
                                """.formatted(licenseKey)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.ticket.userId").isNumber())
                .andExpect(jsonPath("$.ticket.deviceId").value("DEV-23358"))
                .andExpect(jsonPath("$.ticket.blocked").value(false))
                .andExpect(jsonPath("$.signature").isString());

        mockMvc.perform(get("/api/licenses/current")
                        .header("Authorization", "Bearer " + userToken)
                        .param("deviceId", "DEV-23358"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.ticket.deviceId").value("DEV-23358"))
                .andExpect(jsonPath("$.signature").isString());

        mockMvc.perform(post("/api/admin/licenses/{licenseId}/renew", licenseId)
                        .contentType(APPLICATION_JSON)
                        .header("Authorization", "Bearer " + adminToken)
                        .content("""
                                {
                                  "additionalDays": 30
                                }
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(licenseId))
                .andExpect(jsonPath("$.validityDays").value(395));
    }

    private String login(String username, String password) throws Exception {
        final MvcResult result = mockMvc.perform(post("/api/auth/login")
                        .contentType(APPLICATION_JSON)
                        .content("""
                                {
                                  "username": "%s",
                                  "password": "%s"
                                }
                                """.formatted(username, password)))
                .andExpect(status().isOk())
                .andReturn();

        return objectMapper.readTree(result.getResponse().getContentAsString()).get("accessToken").asText();
    }
}
