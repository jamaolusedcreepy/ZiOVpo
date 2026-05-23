package ru.edu.infoguard.server.service;

import static java.nio.charset.StandardCharsets.UTF_8;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;

import org.springframework.stereotype.Service;

@Service
public class AntivirusBasesPackageService {

    private static final byte[] PACKAGE_MAGIC = "IGDB2335".getBytes(UTF_8);
    private static final int PACKAGE_VERSION = 1;
    private static final int SHA256_LENGTH = 32;
    private static final byte[] MANIFEST_SIGNATURE_SECRET = "InfoGuard-AvManifest-23358".getBytes(UTF_8);
    private static final byte[] RECORD_SIGNATURE_SECRET = "InfoGuard-AvRecordSignature-23358".getBytes(UTF_8);
    private static final String RELEASE_DATE = "2026-05-24";

    public byte[] buildCurrentPackage() {
        final List<RecordTemplate> templates = List.of(
                new RecordTemplate(
                        "MZINFOGUARD_DEMO_PE_PAYLOAD_23358".getBytes(UTF_8),
                        0L,
                        256L,
                        1,
                        "Demo.Test.Pe.23358"),
                new RecordTemplate(
                        "Write-Host \"InfoGuard-EICAR-23358\"".getBytes(UTF_8),
                        0L,
                        4096L,
                        2,
                        "Demo.Test.PowerShell.23358"),
                new RecordTemplate(
                        "Write-Output \"InfoGuard-UPDATE-23358\"".getBytes(UTF_8),
                        0L,
                        4096L,
                        2,
                        "Demo.Update.PowerShell.23358"));

        final ByteArrayOutputStream recordsSection = new ByteArrayOutputStream();
        for (RecordTemplate template : templates) {
            final byte[] objectSignature = sha256(template.maliciousBytes());
            final long objectSignaturePrefix = readLittleEndianUInt64(template.maliciousBytes());
            final byte[] threatNameBytes = template.threatName().getBytes(UTF_8);
            final byte[] recordSignature = buildRecordSignature(
                    threatNameBytes,
                    objectSignaturePrefix,
                    template.maliciousBytes().length,
                    objectSignature,
                    template.offsetBegin(),
                    template.offsetEnd(),
                    template.objectType());

            writeInt16(recordsSection, threatNameBytes.length);
            writeInt64(recordsSection, objectSignaturePrefix);
            writeInt32(recordsSection, template.maliciousBytes().length);
            writeInt32(recordsSection, objectSignature.length);
            writeInt64(recordsSection, template.offsetBegin());
            writeInt64(recordsSection, template.offsetEnd());
            writeInt32(recordsSection, template.objectType());
            writeInt32(recordsSection, recordSignature.length);
            recordsSection.writeBytes(objectSignature);
            recordsSection.writeBytes(recordSignature);
            recordsSection.writeBytes(threatNameBytes);
        }

        final byte[] releaseDateBytes = RELEASE_DATE.getBytes(UTF_8);
        final ByteArrayOutputStream packageWithoutManifestSignature = new ByteArrayOutputStream();
        packageWithoutManifestSignature.writeBytes(PACKAGE_MAGIC);
        writeInt32(packageWithoutManifestSignature, PACKAGE_VERSION);
        writeInt16(packageWithoutManifestSignature, releaseDateBytes.length);
        writeInt32(packageWithoutManifestSignature, templates.size());
        writeInt64(packageWithoutManifestSignature, recordsSection.size());
        writeInt32(packageWithoutManifestSignature, SHA256_LENGTH);
        packageWithoutManifestSignature.writeBytes(releaseDateBytes);
        packageWithoutManifestSignature.writeBytes(recordsSection.toByteArray());

        final ByteArrayOutputStream manifestSignatureInput = new ByteArrayOutputStream();
        manifestSignatureInput.writeBytes(packageWithoutManifestSignature.toByteArray());
        manifestSignatureInput.writeBytes(MANIFEST_SIGNATURE_SECRET);
        final byte[] manifestSignature = sha256(manifestSignatureInput.toByteArray());

        final ByteArrayOutputStream result = new ByteArrayOutputStream();
        result.writeBytes(packageWithoutManifestSignature.toByteArray());
        result.writeBytes(manifestSignature);
        return result.toByteArray();
    }

    public String currentReleaseDate() {
        return RELEASE_DATE;
    }

    public int currentRecordCount() {
        return 3;
    }

    private static byte[] buildRecordSignature(
            byte[] threatNameBytes,
            long objectSignaturePrefix,
            int objectSignatureLength,
            byte[] objectSignature,
            long offsetBegin,
            long offsetEnd,
            int objectType) {
        final ByteArrayOutputStream recordSignatureInput = new ByteArrayOutputStream();
        writeInt16(recordSignatureInput, threatNameBytes.length);
        writeInt64(recordSignatureInput, objectSignaturePrefix);
        writeInt32(recordSignatureInput, objectSignatureLength);
        writeInt32(recordSignatureInput, objectSignature.length);
        writeInt64(recordSignatureInput, offsetBegin);
        writeInt64(recordSignatureInput, offsetEnd);
        writeInt32(recordSignatureInput, objectType);
        recordSignatureInput.writeBytes(objectSignature);
        recordSignatureInput.writeBytes(threatNameBytes);
        recordSignatureInput.writeBytes(RECORD_SIGNATURE_SECRET);
        return sha256(recordSignatureInput.toByteArray());
    }

    private static void writeInt16(ByteArrayOutputStream output, int value) {
        output.writeBytes(ByteBuffer.allocate(2).order(ByteOrder.LITTLE_ENDIAN).putShort((short) value).array());
    }

    private static void writeInt32(ByteArrayOutputStream output, int value) {
        output.writeBytes(ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(value).array());
    }

    private static void writeInt64(ByteArrayOutputStream output, long value) {
        output.writeBytes(ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putLong(value).array());
    }

    private static long readLittleEndianUInt64(byte[] bytes) {
        ByteBuffer buffer = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN);
        buffer.put(bytes, 0, 8);
        buffer.flip();
        return buffer.getLong();
    }

    private static byte[] sha256(byte[] data) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(data);
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is not available", exception);
        }
    }

    private record RecordTemplate(
            byte[] maliciousBytes,
            long offsetBegin,
            long offsetEnd,
            int objectType,
            String threatName) {
    }
}
