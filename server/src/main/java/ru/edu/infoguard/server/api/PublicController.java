package ru.edu.infoguard.server.api;

import java.time.Instant;
import java.util.Map;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import ru.edu.infoguard.server.service.AntivirusBasesPackageService;

@RestController
@RequestMapping("/api/public")
public class PublicController {

    private final String applicationName;
    private final AntivirusBasesPackageService antivirusBasesPackageService;

    public PublicController(
            @Value("${spring.application.name}") String applicationName,
            AntivirusBasesPackageService antivirusBasesPackageService) {
        this.applicationName = applicationName;
        this.antivirusBasesPackageService = antivirusBasesPackageService;
    }

    @GetMapping("/ping")
    public Map<String, Object> ping() {
        return Map.of(
                "application", applicationName,
                "status", "ok",
                "timestamp", Instant.now(),
                "transport", "https");
    }

    @GetMapping(value = "/antivirus/bases", produces = MediaType.APPLICATION_OCTET_STREAM_VALUE)
    public ResponseEntity<byte[]> downloadAntivirusBases() {
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"infoguard-antivirus-bases.bin\"")
                .header("X-InfoGuard-Release-Date", antivirusBasesPackageService.currentReleaseDate())
                .header("X-InfoGuard-Record-Count", Integer.toString(antivirusBasesPackageService.currentRecordCount()))
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .body(antivirusBasesPackageService.buildCurrentPackage());
    }
}
