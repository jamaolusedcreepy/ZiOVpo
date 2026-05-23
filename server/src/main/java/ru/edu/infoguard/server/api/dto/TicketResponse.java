package ru.edu.infoguard.server.api.dto;

public record TicketResponse(
        Ticket ticket,
        String signature) {
}
