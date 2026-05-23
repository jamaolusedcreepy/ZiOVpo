#include "antivirus_engine.h"

#include <windows.h>
#include <bcrypt.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <cwctype>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <system_error>

#pragma comment(lib, "Bcrypt.lib")

namespace {

constexpr wchar_t kBasesReleaseDate[] = L"2026-05-23";
constexpr char kRecordSignatureSecret[] = "InfoGuard-AvRecordSignature-23358";
constexpr std::size_t kSha256DigestLength = 32;

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

template <typename IntegerType>
void AppendLittleEndian(std::vector<std::uint8_t>* buffer, const IntegerType value) {
    for (std::size_t index = 0; index < sizeof(IntegerType); ++index) {
        buffer->push_back(static_cast<std::uint8_t>((static_cast<unsigned long long>(value) >> (index * 8)) & 0xffu));
    }
}

std::uint64_t ReadLittleEndianUInt64(const std::uint8_t* data) {
    std::uint64_t value = 0;
    for (std::size_t index = 0; index < sizeof(std::uint64_t); ++index) {
        value |= static_cast<std::uint64_t>(data[index]) << (index * 8);
    }
    return value;
}

bool ComputeSha256(const std::vector<std::uint8_t>& data, std::vector<std::uint8_t>* digest, std::wstring* error_message) {
    error_message->clear();

    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    PUCHAR object_buffer = nullptr;
    DWORD object_length = 0;
    DWORD hash_length = 0;
    DWORD result_length = 0;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    if (status < 0) {
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
    std::vector<std::uint8_t> serialized;
    serialized.reserve(
        sizeof(record.object_signature_prefix) +
        sizeof(record.object_signature_length) +
        record.object_signature.size() +
        sizeof(record.offset_begin) +
        sizeof(record.offset_end) +
        sizeof(unsigned int) +
        sizeof(kRecordSignatureSecret));

    AppendLittleEndian(&serialized, record.object_signature_prefix);
    AppendLittleEndian(&serialized, record.object_signature_length);
    serialized.insert(serialized.end(), record.object_signature.begin(), record.object_signature.end());
    AppendLittleEndian(&serialized, record.offset_begin);
    AppendLittleEndian(&serialized, record.offset_end);
    AppendLittleEndian(&serialized, static_cast<unsigned int>(record.object_type));
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

    if (object_type == ScanObjectType::Unknown || stream.Size() < sizeof(std::uint64_t)) {
        return false;
    }

    for (std::uint64_t position = 0; position + sizeof(std::uint64_t) <= stream.Size(); ++position) {
        std::vector<std::uint8_t> prefix_bytes;
        if (!stream.Read(position, sizeof(std::uint64_t), &prefix_bytes)) {
            *error_message = L"Unable to read the signature prefix while scanning " + path.wstring();
            return false;
        }

        const std::uint64_t prefix = ReadLittleEndianUInt64(prefix_bytes.data());
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

bool AddRecord(
    const std::vector<std::uint8_t>& malicious_bytes,
    const std::uint64_t offset_begin,
    const std::uint64_t offset_end,
    const ScanObjectType object_type,
    const std::wstring& threat_name,
    std::map<std::uint64_t, std::vector<AntivirusEngine::SignatureRecord>>* index,
    unsigned long long* record_count,
    std::wstring* error_message) {
    if (malicious_bytes.size() < sizeof(std::uint64_t)) {
        *error_message = L"Malicious signature is shorter than 8 bytes.";
        return false;
    }

    AntivirusEngine::SignatureRecord record;
    record.object_signature_prefix = ReadLittleEndianUInt64(malicious_bytes.data());
    record.object_signature_length = static_cast<std::uint32_t>(malicious_bytes.size());
    record.offset_begin = offset_begin;
    record.offset_end = offset_end;
    record.object_type = object_type;
    record.threat_name = threat_name;

    if (!ComputeSha256(malicious_bytes, &record.object_signature, error_message)) {
        return false;
    }

    if (!ComputeRecordSignature(record, &record.av_record_signature, error_message)) {
        return false;
    }

    if (!VerifyRecordSignature(record, error_message)) {
        *error_message = L"Generated AV record signature verification failed.";
        return false;
    }

    (*index)[record.object_signature_prefix].push_back(record);
    ++(*record_count);
    return true;
}

}  // namespace

AntivirusEngine::AntivirusEngine() = default;

bool AntivirusEngine::LoadBases(std::wstring* error_message) {
    error_message->clear();

    DatabaseSnapshot loaded_database;
    loaded_database.loaded = true;
    loaded_database.release_date = kBasesReleaseDate;
    loaded_database.record_count = 0;

    if (!AddRecord(
            BytesFromAscii("MZINFOGUARD_DEMO_PE_PAYLOAD_23358"),
            0,
            256,
            ScanObjectType::PeFile,
            L"Demo.Test.Pe.23358",
            &loaded_database.index,
            &loaded_database.record_count,
            error_message)) {
        return false;
    }

    if (!AddRecord(
            BytesFromAscii("Write-Host \"InfoGuard-EICAR-23358\""),
            0,
            4096,
            ScanObjectType::PowerShellScript,
            L"Demo.Test.PowerShell.23358",
            &loaded_database.index,
            &loaded_database.record_count,
            error_message)) {
        return false;
    }

    std::lock_guard<std::mutex> guard(mutex_);
    database_ = std::move(loaded_database);
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
    info.record_count = database_.record_count;
    return info;
}

bool AntivirusEngine::CaptureSnapshot(DatabaseSnapshot* snapshot, std::wstring* error_message) const {
    std::lock_guard<std::mutex> guard(mutex_);
    if (!database_.loaded || database_.record_count == 0) {
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
