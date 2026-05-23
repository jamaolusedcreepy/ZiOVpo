#include "antivirus_engine.h"

#include <windows.h>
#include <bcrypt.h>

#include <algorithm>
#include <cstring>
#include <cwctype>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string_view>
#include <system_error>

#pragma comment(lib, "Bcrypt.lib")

namespace {

constexpr char kPackageMagic[] = "IGDB2335";
constexpr std::uint32_t kPackageVersion = 1;
constexpr wchar_t kBundledReleaseDate[] = L"2026-05-23";
constexpr char kManifestSignatureSecret[] = "InfoGuard-AvManifest-23358";
constexpr char kRecordSignatureSecret[] = "InfoGuard-AvRecordSignature-23358";
constexpr std::uint32_t kSha256DigestLength = 32;
constexpr wchar_t kStorageDirectoryName[] = L"avbases";
constexpr wchar_t kDefaultPackageFileName[] = L"antivirus-bases.default.bin";
constexpr wchar_t kActivePackageFileName[] = L"antivirus-bases.active.bin";
constexpr wchar_t kBackupPackageFileName[] = L"antivirus-bases.backup.bin";

enum class PackageLoadFailure {
    None,
    ManifestInvalid,
    IoFailure,
    FormatFailure,
};

struct RecordTemplate {
    std::vector<std::uint8_t> malicious_bytes;
    std::uint64_t offset_begin = 0;
    std::uint64_t offset_end = 0;
    ScanObjectType object_type = ScanObjectType::Unknown;
    std::wstring threat_name;
};

std::wstring GetLastErrorMessage(const DWORD error_code) {
    LPWSTR buffer = nullptr;
    const DWORD length = FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr,
        error_code,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        reinterpret_cast<LPWSTR>(&buffer),
        0,
        nullptr);

    if (length == 0 || buffer == nullptr) {
        return L"Win32 error " + std::to_wstring(error_code);
    }

    std::wstring result(buffer, length);
    LocalFree(buffer);

    while (!result.empty() && (result.back() == L'\r' || result.back() == L'\n' || result.back() == L' ')) {
        result.pop_back();
    }

    return result;
}

std::wstring ToLowerCopy(std::wstring value) {
    std::transform(value.begin(), value.end(), value.begin(), [](const wchar_t character) {
        return static_cast<wchar_t>(towlower(character));
    });
    return value;
}

std::vector<std::uint8_t> BytesFromAscii(const char* text) {
    const std::size_t length = strlen(text);
    return std::vector<std::uint8_t>(text, text + length);
}

std::string ToUtf8(const std::wstring& value) {
    if (value.empty()) {
        return {};
    }

    const int size = WideCharToMultiByte(
        CP_UTF8,
        0,
        value.data(),
        static_cast<int>(value.size()),
        nullptr,
        0,
        nullptr,
        nullptr);
    std::string result(size > 0 ? size : 0, '\0');
    if (size > 0) {
        WideCharToMultiByte(
            CP_UTF8,
            0,
            value.data(),
            static_cast<int>(value.size()),
            result.data(),
            size,
            nullptr,
            nullptr);
    }
    return result;
}

std::wstring FromUtf8(const std::string& value) {
    if (value.empty()) {
        return {};
    }

    const int size = MultiByteToWideChar(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), nullptr, 0);
    std::wstring result(size > 0 ? size : 0, L'\0');
    if (size > 0) {
        MultiByteToWideChar(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), result.data(), size);
    }
    return result;
}

template <typename IntegerType>
void AppendLittleEndian(std::vector<std::uint8_t>* buffer, const IntegerType value) {
    for (std::size_t index = 0; index < sizeof(IntegerType); ++index) {
        buffer->push_back(static_cast<std::uint8_t>((static_cast<unsigned long long>(value) >> (index * 8)) & 0xffu));
    }
}

template <typename IntegerType>
bool ReadLittleEndian(
    const std::vector<std::uint8_t>& buffer,
    std::size_t* offset,
    IntegerType* value) {
    if (*offset + sizeof(IntegerType) > buffer.size()) {
        return false;
    }

    unsigned long long result = 0;
    for (std::size_t index = 0; index < sizeof(IntegerType); ++index) {
        result |= static_cast<unsigned long long>(buffer[*offset + index]) << (index * 8);
    }

    *value = static_cast<IntegerType>(result);
    *offset += sizeof(IntegerType);
    return true;
}

bool ReadBytes(
    const std::vector<std::uint8_t>& buffer,
    std::size_t* offset,
    const std::size_t length,
    std::vector<std::uint8_t>* value) {
    if (*offset + length > buffer.size()) {
        return false;
    }

    value->assign(
        buffer.begin() + static_cast<std::ptrdiff_t>(*offset),
        buffer.begin() + static_cast<std::ptrdiff_t>(*offset + length));
    *offset += length;
    return true;
}

bool ReadUtf8String(
    const std::vector<std::uint8_t>& buffer,
    std::size_t* offset,
    const std::size_t length,
    std::wstring* value) {
    std::vector<std::uint8_t> bytes;
    if (!ReadBytes(buffer, offset, length, &bytes)) {
        return false;
    }

    *value = FromUtf8(std::string(bytes.begin(), bytes.end()));
    return true;
}

bool ComputeSha256(
    const std::vector<std::uint8_t>& data,
    std::vector<std::uint8_t>* digest,
    std::wstring* error_message) {
    error_message->clear();

    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    PUCHAR object_buffer = nullptr;
    DWORD object_length = 0;
    DWORD hash_length = 0;
    DWORD result_length = 0;

    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0) {
        *error_message = L"BCryptOpenAlgorithmProvider failed while preparing SHA-256.";
        return false;
    }

    const auto close_handles = [&]() {
        if (hash != nullptr) {
            BCryptDestroyHash(hash);
        }
        if (object_buffer != nullptr) {
            HeapFree(GetProcessHeap(), 0, object_buffer);
        }
        if (algorithm != nullptr) {
            BCryptCloseAlgorithmProvider(algorithm, 0);
        }
    };

    if (BCryptGetProperty(
            algorithm,
            BCRYPT_OBJECT_LENGTH,
            reinterpret_cast<PUCHAR>(&object_length),
            sizeof(object_length),
            &result_length,
            0) < 0) {
        close_handles();
        *error_message = L"BCryptGetProperty(BCRYPT_OBJECT_LENGTH) failed.";
        return false;
    }

    if (BCryptGetProperty(
            algorithm,
            BCRYPT_HASH_LENGTH,
            reinterpret_cast<PUCHAR>(&hash_length),
            sizeof(hash_length),
            &result_length,
            0) < 0) {
        close_handles();
        *error_message = L"BCryptGetProperty(BCRYPT_HASH_LENGTH) failed.";
        return false;
    }

    object_buffer = static_cast<PUCHAR>(HeapAlloc(GetProcessHeap(), 0, object_length));
    if (object_buffer == nullptr) {
        close_handles();
        *error_message = L"HeapAlloc failed while creating the SHA-256 hash object.";
        return false;
    }

    if (BCryptCreateHash(algorithm, &hash, object_buffer, object_length, nullptr, 0, 0) < 0) {
        close_handles();
        *error_message = L"BCryptCreateHash failed.";
        return false;
    }

    if (!data.empty() &&
        BCryptHashData(hash, const_cast<PUCHAR>(reinterpret_cast<const UCHAR*>(data.data())), static_cast<ULONG>(data.size()), 0) < 0) {
        close_handles();
        *error_message = L"BCryptHashData failed.";
        return false;
    }

    digest->assign(hash_length, 0);
    if (BCryptFinishHash(hash, digest->data(), hash_length, 0) < 0) {
        close_handles();
        *error_message = L"BCryptFinishHash failed.";
        return false;
    }

    close_handles();
    return true;
}

std::vector<std::uint8_t> SerializeRecordForSignature(const AntivirusEngine::SignatureRecord& record) {
    const std::string threat_name_utf8 = ToUtf8(record.threat_name);
    std::vector<std::uint8_t> serialized;
    serialized.reserve(
        sizeof(std::uint16_t) +
        sizeof(record.object_signature_prefix) +
        sizeof(record.object_signature_length) +
        sizeof(std::uint32_t) +
        sizeof(record.offset_begin) +
        sizeof(record.offset_end) +
        sizeof(std::uint32_t) +
        threat_name_utf8.size() +
        record.object_signature.size() +
        strlen(kRecordSignatureSecret));

    AppendLittleEndian(&serialized, static_cast<std::uint16_t>(threat_name_utf8.size()));
    AppendLittleEndian(&serialized, record.object_signature_prefix);
    AppendLittleEndian(&serialized, record.object_signature_length);
    AppendLittleEndian(&serialized, static_cast<std::uint32_t>(record.object_signature.size()));
    AppendLittleEndian(&serialized, record.offset_begin);
    AppendLittleEndian(&serialized, record.offset_end);
    AppendLittleEndian(&serialized, static_cast<std::uint32_t>(record.object_type));
    serialized.insert(serialized.end(), record.object_signature.begin(), record.object_signature.end());
    serialized.insert(serialized.end(), threat_name_utf8.begin(), threat_name_utf8.end());
    serialized.insert(
        serialized.end(),
        reinterpret_cast<const std::uint8_t*>(kRecordSignatureSecret),
        reinterpret_cast<const std::uint8_t*>(kRecordSignatureSecret) + strlen(kRecordSignatureSecret));
    return serialized;
}

bool ComputeRecordSignature(
    const AntivirusEngine::SignatureRecord& record,
    std::vector<std::uint8_t>* signature,
    std::wstring* error_message) {
    return ComputeSha256(SerializeRecordForSignature(record), signature, error_message);
}

bool VerifyRecordSignature(
    const AntivirusEngine::SignatureRecord& record,
    std::wstring* error_message) {
    std::vector<std::uint8_t> expected_signature;
    if (!ComputeRecordSignature(record, &expected_signature, error_message)) {
        return false;
    }

    return expected_signature == record.av_record_signature;
}

std::wstring ScanObjectTypeToString(const ScanObjectType object_type) {
    switch (object_type) {
    case ScanObjectType::PeFile:
        return L"PE file";
    case ScanObjectType::PowerShellScript:
        return L"PowerShell script";
    default:
        return L"Unknown";
    }
}

class MemoryByteStream {
public:
    bool LoadFromFile(const std::filesystem::path& path, std::wstring* error_message) {
        std::ifstream input(path, std::ios::binary);
        if (!input.is_open()) {
            *error_message = L"Unable to open file for scanning: " + path.wstring();
            return false;
        }

        input.seekg(0, std::ios::end);
        const std::streamoff length = input.tellg();
        input.seekg(0, std::ios::beg);

        if (length < 0) {
            *error_message = L"Unable to determine file size for scanning: " + path.wstring();
            return false;
        }

        bytes_.assign(static_cast<std::size_t>(length), 0);
        if (length > 0) {
            input.read(reinterpret_cast<char*>(bytes_.data()), length);
            if (!input.good() && !input.eof()) {
                *error_message = L"Failed while reading file content: " + path.wstring();
                return false;
            }
        }

        return true;
    }

    std::uint64_t Size() const {
        return static_cast<std::uint64_t>(bytes_.size());
    }

    bool Read(std::uint64_t offset, std::size_t length, std::vector<std::uint8_t>* chunk) const {
        if (offset > bytes_.size() || length > bytes_.size() - static_cast<std::size_t>(offset)) {
            return false;
        }

        chunk->assign(
            bytes_.begin() + static_cast<std::ptrdiff_t>(offset),
            bytes_.begin() + static_cast<std::ptrdiff_t>(offset + length));
        return true;
    }

private:
    std::vector<std::uint8_t> bytes_;
};

ScanObjectType DetectObjectType(const std::filesystem::path& path, const MemoryByteStream& stream) {
    std::vector<std::uint8_t> header;
    if (stream.Read(0, 2, &header) && header.size() == 2 && header[0] == 'M' && header[1] == 'Z') {
        return ScanObjectType::PeFile;
    }

    const std::wstring extension = ToLowerCopy(path.extension().wstring());
    if (extension == L".ps1" || extension == L".psm1" || extension == L".psd1") {
        return ScanObjectType::PowerShellScript;
    }

    return ScanObjectType::Unknown;
}

bool ScanStreamForThreat(
    const MemoryByteStream& stream,
    const std::filesystem::path& path,
    const AntivirusEngine::DatabaseSnapshot& database,
    ScanResultInfo* result,
    std::wstring* error_message) {
    const ScanObjectType object_type = DetectObjectType(path, stream);
    result->object_type = ScanObjectTypeToString(object_type);

    if (database.index.empty() || object_type == ScanObjectType::Unknown || stream.Size() < sizeof(std::uint64_t)) {
        result->summary = L"No threats were detected in the selected object.";
        return false;
    }

    for (std::uint64_t position = 0; position + sizeof(std::uint64_t) <= stream.Size(); ++position) {
        std::vector<std::uint8_t> prefix_bytes;
        if (!stream.Read(position, sizeof(std::uint64_t), &prefix_bytes)) {
            *error_message = L"Unable to read the signature prefix while scanning " + path.wstring();
            return false;
        }

        std::uint64_t prefix = 0;
        for (std::size_t index = 0; index < sizeof(std::uint64_t); ++index) {
            prefix |= static_cast<std::uint64_t>(prefix_bytes[index]) << (index * 8);
        }

        const auto iterator = database.index.find(prefix);
        if (iterator == database.index.end()) {
            continue;
        }

        for (const auto& record : iterator->second) {
            if (record.object_type != object_type) {
                continue;
            }

            if (position < record.offset_begin || position > record.offset_end) {
                continue;
            }

            if (position + record.object_signature_length > stream.Size()) {
                continue;
            }

            std::vector<std::uint8_t> object_bytes;
            if (!stream.Read(position, record.object_signature_length, &object_bytes)) {
                *error_message = L"Unable to read the candidate signature bytes while scanning " + path.wstring();
                return false;
            }

            std::vector<std::uint8_t> digest;
            if (!ComputeSha256(object_bytes, &digest, error_message)) {
                return false;
            }

            if (digest != record.object_signature) {
                continue;
            }

            result->malicious = true;
            result->infected_object_count = 1;
            result->detected_path = path.wstring();
            result->detected_threat_name = record.threat_name;
            std::wostringstream summary;
            summary << L"Threat detected in " << path.wstring() << L"\r\n"
                    << L"Threat name: " << record.threat_name << L"\r\n"
                    << L"Object type: " << result->object_type << L"\r\n"
                    << L"Detection offset: " << position;
            result->summary = summary.str();
            return true;
        }
    }

    result->summary = L"No threats were detected in the selected object.";
    return false;
}

std::vector<RecordTemplate> BuildBundledRecordTemplates() {
    return {
        RecordTemplate{
            BytesFromAscii("MZINFOGUARD_DEMO_PE_PAYLOAD_23358"),
            0,
            256,
            ScanObjectType::PeFile,
            L"Demo.Test.Pe.23358",
        },
        RecordTemplate{
            BytesFromAscii("Write-Host \"InfoGuard-EICAR-23358\""),
            0,
            4096,
            ScanObjectType::PowerShellScript,
            L"Demo.Test.PowerShell.23358",
        },
    };
}

bool BuildPackageFromTemplates(
    const std::vector<RecordTemplate>& templates,
    const std::wstring& release_date,
    std::vector<std::uint8_t>* package_bytes,
    std::wstring* error_message) {
    std::vector<AntivirusEngine::SignatureRecord> records;
    records.reserve(templates.size());

    for (const auto& entry : templates) {
        if (entry.malicious_bytes.size() < sizeof(std::uint64_t)) {
            *error_message = L"One of the bundled signatures is shorter than 8 bytes.";
            return false;
        }

        AntivirusEngine::SignatureRecord record;
        record.object_signature_prefix = 0;
        for (std::size_t index = 0; index < sizeof(std::uint64_t); ++index) {
            record.object_signature_prefix |= static_cast<std::uint64_t>(entry.malicious_bytes[index]) << (index * 8);
        }
        record.object_signature_length = static_cast<std::uint32_t>(entry.malicious_bytes.size());
        record.offset_begin = entry.offset_begin;
        record.offset_end = entry.offset_end;
        record.object_type = entry.object_type;
        record.threat_name = entry.threat_name;

        if (!ComputeSha256(entry.malicious_bytes, &record.object_signature, error_message)) {
            return false;
        }

        if (!ComputeRecordSignature(record, &record.av_record_signature, error_message)) {
            return false;
        }

        records.push_back(std::move(record));
    }

    const std::string release_date_utf8 = ToUtf8(release_date);
    std::vector<std::uint8_t> package_without_manifest_signature;
    package_without_manifest_signature.reserve(1024);

    package_without_manifest_signature.insert(
        package_without_manifest_signature.end(),
        reinterpret_cast<const std::uint8_t*>(kPackageMagic),
        reinterpret_cast<const std::uint8_t*>(kPackageMagic) + sizeof(kPackageMagic) - 1);
    AppendLittleEndian(&package_without_manifest_signature, kPackageVersion);
    AppendLittleEndian(&package_without_manifest_signature, static_cast<std::uint16_t>(release_date_utf8.size()));
    AppendLittleEndian(&package_without_manifest_signature, static_cast<std::uint32_t>(records.size()));

    std::vector<std::uint8_t> records_section;
    for (const auto& record : records) {
        const std::string threat_name_utf8 = ToUtf8(record.threat_name);
        AppendLittleEndian(&records_section, static_cast<std::uint16_t>(threat_name_utf8.size()));
        AppendLittleEndian(&records_section, record.object_signature_prefix);
        AppendLittleEndian(&records_section, record.object_signature_length);
        AppendLittleEndian(&records_section, static_cast<std::uint32_t>(record.object_signature.size()));
        AppendLittleEndian(&records_section, record.offset_begin);
        AppendLittleEndian(&records_section, record.offset_end);
        AppendLittleEndian(&records_section, static_cast<std::uint32_t>(record.object_type));
        AppendLittleEndian(&records_section, static_cast<std::uint32_t>(record.av_record_signature.size()));
        records_section.insert(records_section.end(), record.object_signature.begin(), record.object_signature.end());
        records_section.insert(records_section.end(), record.av_record_signature.begin(), record.av_record_signature.end());
        records_section.insert(records_section.end(), threat_name_utf8.begin(), threat_name_utf8.end());
    }

    AppendLittleEndian(&package_without_manifest_signature, static_cast<std::uint64_t>(records_section.size()));
    AppendLittleEndian(&package_without_manifest_signature, static_cast<std::uint32_t>(kSha256DigestLength));
    package_without_manifest_signature.insert(
        package_without_manifest_signature.end(),
        release_date_utf8.begin(),
        release_date_utf8.end());
    package_without_manifest_signature.insert(
        package_without_manifest_signature.end(),
        records_section.begin(),
        records_section.end());

    std::vector<std::uint8_t> manifest_signature_input = package_without_manifest_signature;
    manifest_signature_input.insert(
        manifest_signature_input.end(),
        reinterpret_cast<const std::uint8_t*>(kManifestSignatureSecret),
        reinterpret_cast<const std::uint8_t*>(kManifestSignatureSecret) + strlen(kManifestSignatureSecret));

    std::vector<std::uint8_t> manifest_signature;
    if (!ComputeSha256(manifest_signature_input, &manifest_signature, error_message)) {
        return false;
    }

    *package_bytes = std::move(package_without_manifest_signature);
    package_bytes->insert(package_bytes->end(), manifest_signature.begin(), manifest_signature.end());
    return true;
}

bool EnsureDirectoryExists(const std::filesystem::path& path, std::wstring* error_message) {
    std::error_code error_code;
    std::filesystem::create_directories(path, error_code);
    if (error_code) {
        *error_message = L"Unable to create antivirus storage directory " + path.wstring() + L": " +
            FromUtf8(error_code.message());
        return false;
    }

    return true;
}

bool ReadFileBytes(
    const std::filesystem::path& path,
    std::vector<std::uint8_t>* bytes,
    std::wstring* error_message) {
    std::ifstream input(path, std::ios::binary);
    if (!input.is_open()) {
        *error_message = L"Unable to open antivirus bases file " + path.wstring();
        return false;
    }

    input.seekg(0, std::ios::end);
    const std::streamoff length = input.tellg();
    input.seekg(0, std::ios::beg);
    if (length < 0) {
        *error_message = L"Unable to determine antivirus bases file size for " + path.wstring();
        return false;
    }

    bytes->assign(static_cast<std::size_t>(length), 0);
    if (length > 0) {
        input.read(reinterpret_cast<char*>(bytes->data()), length);
        if (!input.good() && !input.eof()) {
            *error_message = L"Unable to read antivirus bases file " + path.wstring();
            return false;
        }
    }

    return true;
}

bool WriteFileBytes(
    const std::filesystem::path& path,
    const std::vector<std::uint8_t>& bytes,
    std::wstring* error_message) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    if (!output.is_open()) {
        *error_message = L"Unable to write antivirus bases file " + path.wstring();
        return false;
    }

    if (!bytes.empty()) {
        output.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
        if (!output.good()) {
            *error_message = L"Unable to persist antivirus bases file " + path.wstring();
            return false;
        }
    }

    return true;
}

bool CopyFileReplace(
    const std::filesystem::path& source,
    const std::filesystem::path& destination,
    std::wstring* error_message) {
    std::error_code error_code;
    std::filesystem::copy_file(source, destination, std::filesystem::copy_options::overwrite_existing, error_code);
    if (error_code) {
        *error_message = L"Unable to copy antivirus bases from " + source.wstring() + L" to " + destination.wstring() +
            L": " + FromUtf8(error_code.message());
        return false;
    }

    return true;
}

bool RemoveIfExists(const std::filesystem::path& path) {
    std::error_code error_code;
    std::filesystem::remove(path, error_code);
    return !error_code;
}

bool ParsePackageBytes(
    const std::vector<std::uint8_t>& bytes,
    const std::wstring& source_path,
    AntivirusEngine::DatabaseSnapshot* snapshot,
    PackageLoadFailure* failure,
    std::wstring* error_message) {
    *failure = PackageLoadFailure::None;
    error_message->clear();

    if (bytes.size() < (sizeof(kPackageMagic) - 1) + sizeof(std::uint32_t) + sizeof(std::uint16_t) +
            sizeof(std::uint32_t) + sizeof(std::uint64_t) + sizeof(std::uint32_t) + kSha256DigestLength) {
        *failure = PackageLoadFailure::FormatFailure;
        *error_message = L"Antivirus bases file is too short to contain a valid manifest.";
        return false;
    }

    std::size_t offset = 0;
    std::vector<std::uint8_t> magic_bytes;
    if (!ReadBytes(bytes, &offset, sizeof(kPackageMagic) - 1, &magic_bytes)) {
        *failure = PackageLoadFailure::FormatFailure;
        *error_message = L"Unable to read the package magic.";
        return false;
    }

    if (memcmp(magic_bytes.data(), kPackageMagic, sizeof(kPackageMagic) - 1) != 0) {
        *failure = PackageLoadFailure::FormatFailure;
        *error_message = L"Antivirus bases file has an unexpected magic value.";
        return false;
    }

    std::uint32_t package_version = 0;
    std::uint16_t release_date_length = 0;
    std::uint32_t declared_record_count = 0;
    std::uint64_t records_section_length = 0;
    std::uint32_t manifest_signature_length = 0;
    if (!ReadLittleEndian(bytes, &offset, &package_version) ||
        !ReadLittleEndian(bytes, &offset, &release_date_length) ||
        !ReadLittleEndian(bytes, &offset, &declared_record_count) ||
        !ReadLittleEndian(bytes, &offset, &records_section_length) ||
        !ReadLittleEndian(bytes, &offset, &manifest_signature_length)) {
        *failure = PackageLoadFailure::FormatFailure;
        *error_message = L"Unable to read the antivirus bases manifest header.";
        return false;
    }

    if (package_version != kPackageVersion) {
        *failure = PackageLoadFailure::FormatFailure;
        *error_message = L"Antivirus bases package version is unsupported.";
        return false;
    }

    if (manifest_signature_length == 0 || manifest_signature_length > 1024) {
        *failure = PackageLoadFailure::FormatFailure;
        *error_message = L"Antivirus bases manifest signature length is invalid.";
        return false;
    }

    const std::size_t manifest_payload_length =
        (sizeof(kPackageMagic) - 1) +
        sizeof(package_version) +
        sizeof(release_date_length) +
        sizeof(declared_record_count) +
        sizeof(records_section_length) +
        sizeof(manifest_signature_length) +
        release_date_length +
        static_cast<std::size_t>(records_section_length);

    if (manifest_payload_length + manifest_signature_length != bytes.size()) {
        *failure = PackageLoadFailure::FormatFailure;
        *error_message = L"Antivirus bases manifest size does not match the file content.";
        return false;
    }

    std::wstring release_date;
    if (!ReadUtf8String(bytes, &offset, release_date_length, &release_date)) {
        *failure = PackageLoadFailure::FormatFailure;
        *error_message = L"Unable to read the antivirus bases release date.";
        return false;
    }

    const std::size_t records_section_begin = offset;
    const std::size_t records_section_end = records_section_begin + static_cast<std::size_t>(records_section_length);
    if (offset + static_cast<std::size_t>(records_section_length) > bytes.size()) {
        *failure = PackageLoadFailure::FormatFailure;
        *error_message = L"Unable to read the antivirus bases records section.";
        return false;
    }
    offset += static_cast<std::size_t>(records_section_length);

    std::vector<std::uint8_t> stored_manifest_signature;
    if (!ReadBytes(bytes, &offset, manifest_signature_length, &stored_manifest_signature)) {
        *failure = PackageLoadFailure::FormatFailure;
        *error_message = L"Unable to read the manifest signature.";
        return false;
    }

    std::vector<std::uint8_t> manifest_signature_input(
        bytes.begin(),
        bytes.begin() + static_cast<std::ptrdiff_t>(bytes.size() - manifest_signature_length));
    manifest_signature_input.insert(
        manifest_signature_input.end(),
        reinterpret_cast<const std::uint8_t*>(kManifestSignatureSecret),
        reinterpret_cast<const std::uint8_t*>(kManifestSignatureSecret) + strlen(kManifestSignatureSecret));

    std::vector<std::uint8_t> expected_manifest_signature;
    if (!ComputeSha256(manifest_signature_input, &expected_manifest_signature, error_message)) {
        *failure = PackageLoadFailure::FormatFailure;
        return false;
    }

    if (stored_manifest_signature != expected_manifest_signature) {
        *failure = PackageLoadFailure::ManifestInvalid;
        *error_message = L"Antivirus bases manifest signature verification failed.";
        return false;
    }

    AntivirusEngine::DatabaseSnapshot parsed_snapshot;
    parsed_snapshot.loaded = true;
    parsed_snapshot.release_date = release_date;
    parsed_snapshot.source_path = source_path;

    std::size_t record_offset = records_section_begin;
    for (std::uint32_t record_index = 0; record_index < declared_record_count; ++record_index) {
        std::uint16_t threat_name_length = 0;
        std::uint64_t object_signature_prefix = 0;
        std::uint32_t object_signature_length = 0;
        std::uint32_t object_signature_digest_length = 0;
        std::uint64_t offset_begin = 0;
        std::uint64_t offset_end = 0;
        std::uint32_t object_type_raw = 0;
        std::uint32_t record_signature_length = 0;

        if (!ReadLittleEndian(bytes, &record_offset, &threat_name_length) ||
            !ReadLittleEndian(bytes, &record_offset, &object_signature_prefix) ||
            !ReadLittleEndian(bytes, &record_offset, &object_signature_length) ||
            !ReadLittleEndian(bytes, &record_offset, &object_signature_digest_length) ||
            !ReadLittleEndian(bytes, &record_offset, &offset_begin) ||
            !ReadLittleEndian(bytes, &record_offset, &offset_end) ||
            !ReadLittleEndian(bytes, &record_offset, &object_type_raw) ||
            !ReadLittleEndian(bytes, &record_offset, &record_signature_length)) {
            *failure = PackageLoadFailure::FormatFailure;
            *error_message = L"Unable to read one of the antivirus records from " + source_path;
            return false;
        }

        if (object_signature_digest_length == 0 || object_signature_digest_length > 1024 ||
            record_signature_length == 0 || record_signature_length > 1024) {
            *failure = PackageLoadFailure::FormatFailure;
            *error_message = L"An antivirus record has an invalid hash/signature length.";
            return false;
        }

        AntivirusEngine::SignatureRecord record;
        record.object_signature_prefix = object_signature_prefix;
        record.object_signature_length = object_signature_length;
        record.offset_begin = offset_begin;
        record.offset_end = offset_end;
        record.object_type = static_cast<ScanObjectType>(object_type_raw);

        if (!ReadBytes(bytes, &record_offset, object_signature_digest_length, &record.object_signature) ||
            !ReadBytes(bytes, &record_offset, record_signature_length, &record.av_record_signature) ||
            !ReadUtf8String(bytes, &record_offset, threat_name_length, &record.threat_name)) {
            *failure = PackageLoadFailure::FormatFailure;
            *error_message = L"Unable to read the body of an antivirus record from " + source_path;
            return false;
        }

        std::wstring record_error;
        if (!VerifyRecordSignature(record, &record_error)) {
            ++parsed_snapshot.skipped_record_count;
            continue;
        }

        parsed_snapshot.index[record.object_signature_prefix].push_back(record);
        ++parsed_snapshot.record_count;
    }

    if (record_offset != records_section_end) {
        *failure = PackageLoadFailure::FormatFailure;
        *error_message = L"Antivirus records section size mismatch detected in " + source_path;
        return false;
    }

    *snapshot = std::move(parsed_snapshot);
    return true;
}

bool ApplyLoadedSnapshot(
    AntivirusEngine::DatabaseSnapshot snapshot,
    AntivirusEngine::DatabaseSnapshot* destination,
    std::mutex* mutex) {
    std::lock_guard<std::mutex> guard(*mutex);
    *destination = std::move(snapshot);
    return true;
}

}  // namespace

AntivirusEngine::AntivirusEngine() = default;

bool AntivirusEngine::InitializeStorage(const std::wstring& service_module_directory, std::wstring* error_message) {
    module_directory_ = service_module_directory;
    const std::filesystem::path storage_path =
        std::filesystem::path(service_module_directory) / kStorageDirectoryName;
    storage_directory_ = storage_path.wstring();
    default_database_path_ = (storage_path / kDefaultPackageFileName).wstring();
    active_database_path_ = (storage_path / kActivePackageFileName).wstring();
    backup_database_path_ = (storage_path / kBackupPackageFileName).wstring();

    if (!EnsureDirectoryExists(storage_path, error_message)) {
        return false;
    }

    std::vector<std::uint8_t> bundled_package;
    if (!BuildPackageFromTemplates(BuildBundledRecordTemplates(), kBundledReleaseDate, &bundled_package, error_message)) {
        return false;
    }

    if (!WriteFileBytes(default_database_path_, bundled_package, error_message)) {
        return false;
    }

    return LoadBasesFromStorage(error_message);
}

bool AntivirusEngine::LoadBasesFromStorage(std::wstring* error_message) {
    error_message->clear();

    if (active_database_path_.empty()) {
        *error_message = L"Antivirus storage paths are not initialized.";
        return false;
    }

    const std::filesystem::path active_path(active_database_path_);
    const std::filesystem::path backup_path(backup_database_path_);
    const std::filesystem::path default_path(default_database_path_);

    if (!std::filesystem::exists(active_path)) {
        if (!CopyFileReplace(default_path, active_path, error_message)) {
            return false;
        }
    }

    const auto try_load_path = [&](const std::filesystem::path& path, DatabaseSnapshot* snapshot, PackageLoadFailure* failure) {
        std::vector<std::uint8_t> bytes;
        if (!ReadFileBytes(path, &bytes, error_message)) {
            *failure = PackageLoadFailure::IoFailure;
            return false;
        }

        return ParsePackageBytes(bytes, path.wstring(), snapshot, failure, error_message);
    };

    DatabaseSnapshot snapshot;
    PackageLoadFailure failure = PackageLoadFailure::None;
    if (try_load_path(active_path, &snapshot, &failure)) {
        ApplyLoadedSnapshot(std::move(snapshot), &database_, &mutex_);
        return true;
    }

    if (std::filesystem::exists(backup_path)) {
        std::wstring backup_error;
        if (CopyFileReplace(backup_path, active_path, &backup_error)) {
            DatabaseSnapshot backup_snapshot;
            PackageLoadFailure backup_failure = PackageLoadFailure::None;
            if (try_load_path(active_path, &backup_snapshot, &backup_failure)) {
                ApplyLoadedSnapshot(std::move(backup_snapshot), &database_, &mutex_);
                error_message->clear();
                return true;
            }
        }
    }

    std::wstring default_error;
    if (!CopyFileReplace(default_path, active_path, &default_error)) {
        *error_message = default_error;
        return false;
    }

    DatabaseSnapshot default_snapshot;
    PackageLoadFailure default_failure = PackageLoadFailure::None;
    if (!try_load_path(active_path, &default_snapshot, &default_failure)) {
        return false;
    }

    ApplyLoadedSnapshot(std::move(default_snapshot), &database_, &mutex_);
    error_message->clear();
    return true;
}

bool AntivirusEngine::UpdateBasesFromPackage(
    const std::vector<std::uint8_t>& package_bytes,
    std::wstring* error_message) {
    error_message->clear();

    if (active_database_path_.empty()) {
        *error_message = L"Antivirus storage paths are not initialized.";
        return false;
    }

    DatabaseSnapshot updated_snapshot;
    PackageLoadFailure failure = PackageLoadFailure::None;
    if (!ParsePackageBytes(package_bytes, L"downloaded update package", &updated_snapshot, &failure, error_message)) {
        return false;
    }

    const std::filesystem::path active_path(active_database_path_);
    const std::filesystem::path backup_path(backup_database_path_);
    const std::filesystem::path temp_path = active_path.wstring() + L".tmp";

    if (std::filesystem::exists(active_path)) {
        if (!CopyFileReplace(active_path, backup_path, error_message)) {
            return false;
        }
    }

    if (!WriteFileBytes(temp_path, package_bytes, error_message)) {
        if (std::filesystem::exists(backup_path)) {
            std::wstring ignored_error;
            CopyFileReplace(backup_path, active_path, &ignored_error);
        }
        return false;
    }

    std::error_code move_error;
    std::filesystem::rename(temp_path, active_path, move_error);
    if (move_error) {
        RemoveIfExists(active_path);
        move_error.clear();
        std::filesystem::rename(temp_path, active_path, move_error);
        if (move_error) {
            RemoveIfExists(temp_path);
            if (std::filesystem::exists(backup_path)) {
                std::wstring ignored_error;
                CopyFileReplace(backup_path, active_path, &ignored_error);
            }
            *error_message = L"Unable to replace antivirus bases with the downloaded update: " +
                FromUtf8(move_error.message());
            return false;
        }
    }

    ApplyLoadedSnapshot(std::move(updated_snapshot), &database_, &mutex_);
    return true;
}

void AntivirusEngine::UnloadBases() {
    std::lock_guard<std::mutex> guard(mutex_);
    database_ = DatabaseSnapshot{};
}

AntivirusBasesInfo AntivirusEngine::GetBasesInfo() const {
    std::lock_guard<std::mutex> guard(mutex_);
    AntivirusBasesInfo info;
    info.loaded = database_.loaded;
    info.release_date = database_.release_date;
    info.source_path = database_.source_path;
    info.record_count = database_.record_count;
    info.skipped_record_count = database_.skipped_record_count;
    return info;
}

bool AntivirusEngine::CaptureSnapshot(DatabaseSnapshot* snapshot, std::wstring* error_message) const {
    std::lock_guard<std::mutex> guard(mutex_);
    if (!database_.loaded) {
        *error_message = L"Antivirus bases are not loaded in the Windows service.";
        return false;
    }

    *snapshot = database_;
    return true;
}

DWORD AntivirusEngine::ScanFile(
    const std::wstring& file_path,
    ScanResultInfo* result,
    std::wstring* error_message) const {
    error_message->clear();
    *result = ScanResultInfo{};
    result->target_path = file_path;
    result->directory_scan = false;

    DatabaseSnapshot database;
    if (!CaptureSnapshot(&database, error_message)) {
        return ERROR_NOT_READY;
    }

    const std::filesystem::path path(file_path);
    if (!std::filesystem::exists(path)) {
        *error_message = L"The selected file does not exist.";
        return ERROR_FILE_NOT_FOUND;
    }

    if (!std::filesystem::is_regular_file(path)) {
        *error_message = L"The selected path is not a regular file.";
        return ERROR_INVALID_PARAMETER;
    }

    MemoryByteStream stream;
    if (!stream.LoadFromFile(path, error_message)) {
        return ERROR_OPEN_FAILED;
    }

    result->scanned_object_count = 1;
    if (!ScanStreamForThreat(stream, path, database, result, error_message)) {
        if (!error_message->empty()) {
            return ERROR_BAD_FORMAT;
        }

        std::wostringstream summary;
        summary << L"File scan finished.\r\n"
                << L"Target: " << file_path << L"\r\n"
                << L"Object type: " << result->object_type << L"\r\n"
                << L"Threats detected: no";
        result->summary = summary.str();
        return ERROR_SUCCESS;
    }

    std::wostringstream summary;
    summary << L"File scan finished.\r\n"
            << L"Target: " << file_path << L"\r\n"
            << L"Object type: " << result->object_type << L"\r\n"
            << L"Threats detected: yes\r\n"
            << L"Threat name: " << result->detected_threat_name;
    result->summary = summary.str();
    return ERROR_SUCCESS;
}

DWORD AntivirusEngine::ScanDirectory(
    const std::wstring& directory_path,
    ScanResultInfo* result,
    std::wstring* error_message) const {
    error_message->clear();
    *result = ScanResultInfo{};
    result->target_path = directory_path;
    result->directory_scan = true;

    DatabaseSnapshot database;
    if (!CaptureSnapshot(&database, error_message)) {
        return ERROR_NOT_READY;
    }

    const std::filesystem::path path(directory_path);
    if (!std::filesystem::exists(path)) {
        *error_message = L"The selected directory does not exist.";
        return ERROR_PATH_NOT_FOUND;
    }

    if (!std::filesystem::is_directory(path)) {
        *error_message = L"The selected path is not a directory.";
        return ERROR_DIRECTORY;
    }

    std::vector<std::wstring> infected_paths;
    std::error_code iteration_error;
    std::filesystem::recursive_directory_iterator iterator(
        path,
        std::filesystem::directory_options::skip_permission_denied,
        iteration_error);
    const std::filesystem::recursive_directory_iterator end;

    for (; iterator != end; iterator.increment(iteration_error)) {
        if (iteration_error) {
            iteration_error.clear();
            continue;
        }

        if (!iterator->is_regular_file()) {
            continue;
        }

        ScanResultInfo file_result;
        std::wstring local_error;
        const DWORD status = ScanFile(iterator->path().wstring(), &file_result, &local_error);
        if (status != ERROR_SUCCESS) {
            continue;
        }

        ++result->scanned_object_count;
        if (file_result.malicious) {
            ++result->infected_object_count;
            if (result->detected_path.empty()) {
                result->detected_path = file_result.detected_path;
                result->detected_threat_name = file_result.detected_threat_name;
                result->object_type = file_result.object_type;
            }

            if (infected_paths.size() < 5) {
                infected_paths.push_back(file_result.detected_path);
            }
        }
    }

    result->malicious = result->infected_object_count > 0;

    std::wostringstream summary;
    summary << L"Directory scan finished.\r\n"
            << L"Target: " << directory_path << L"\r\n"
            << L"Files scanned: " << result->scanned_object_count << L"\r\n"
            << L"Infected files: " << result->infected_object_count;
    if (!infected_paths.empty()) {
        summary << L"\r\n\r\nFirst detected threat: " << result->detected_threat_name
                << L"\r\nSample infected paths:";
        for (const auto& infected_path : infected_paths) {
            summary << L"\r\n- " << infected_path;
        }
    }

    result->summary = summary.str();
    return ERROR_SUCCESS;
}
