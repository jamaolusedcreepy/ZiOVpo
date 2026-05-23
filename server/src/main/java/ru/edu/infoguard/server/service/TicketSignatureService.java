package ru.edu.infoguard.server.service;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.stereotype.Service;

import ru.edu.infoguard.server.api.dto.Ticket;
import ru.edu.infoguard.server.config.LicenseProperties;

@Service
public class TicketSignatureService {

    private final LicenseProperties licenseProperties;

    public TicketSignatureService(LicenseProperties licenseProperties) {
        this.licenseProperties = licenseProperties;
    }

    public String sign(Ticket ticket) {
        try {
            final Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(
                    licenseProperties.ticketSignatureSecret().getBytes(StandardCharsets.UTF_8),
                    "HmacSHA256"));

            final String payload = ticket.serverDate() + "|" +
                    ticket.ticketLifetimeSeconds() + "|" +
                    ticket.licenseActivatedAt() + "|" +
                    ticket.licenseExpiresAt() + "|" +
                    ticket.userId() + "|" +
                    ticket.deviceId() + "|" +
                    ticket.blocked();

            final byte[] signature = mac.doFinal(payload.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(signature);
        } catch (Exception exception) {
            throw new IllegalStateException("Failed to sign the license ticket", exception);
        }
    }
}
