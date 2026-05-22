package ru.edu.infoguard.server.api;

import java.time.Instant;
import java.util.Map;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/public")
public class PublicController {

    private final String applicationName;

    public PublicController(@Value("${spring.application.name}") String applicationName) {
        this.applicationName = applicationName;
    }

    @GetMapping("/ping")
    public Map<String, Object> ping() {
        return Map.of(
                "application", applicationName,
                "status", "ok",
                "timestamp", Instant.now(),
                "transport", "https");
    }
}
