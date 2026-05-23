#pragma once

#include <windows.h>

#include <cstdint>
#include <map>
#include <mutex>
#include <string>
#include <vector>

enum class ScanObjectType : unsigned int {
    Unknown = 0,
    PeFile = 1,
    PowerShellScript = 2,
};

struct AntivirusBasesInfo {
    bool loaded = false;
    std::wstring release_date;
    unsigned long long record_count = 0;
};

struct ScanResultInfo {
    bool malicious = false;
    bool directory_scan = false;
    unsigned long long scanned_object_count = 0;
    unsigned long long infected_object_count = 0;
    std::wstring target_path;
    std::wstring detected_path;
    std::wstring detected_threat_name;
    std::wstring object_type;
    std::wstring summary;
};

class AntivirusEngine {
public:
    AntivirusEngine();

    bool LoadBases(std::wstring* error_message);
    void UnloadBases();
    AntivirusBasesInfo GetBasesInfo() const;

    DWORD ScanFile(
        const std::wstring& file_path,
        ScanResultInfo* result,
        std::wstring* error_message) const;

    DWORD ScanDirectory(
        const std::wstring& directory_path,
        ScanResultInfo* result,
        std::wstring* error_message) const;

    struct SignatureRecord {
        std::uint64_t object_signature_prefix = 0;
        std::uint32_t object_signature_length = 0;
        std::vector<std::uint8_t> object_signature;
        std::uint64_t offset_begin = 0;
        std::uint64_t offset_end = 0;
        ScanObjectType object_type = ScanObjectType::Unknown;
        std::vector<std::uint8_t> av_record_signature;
        std::wstring threat_name;
    };

    struct DatabaseSnapshot {
        bool loaded = false;
        std::wstring release_date;
        unsigned long long record_count = 0;
        std::map<std::uint64_t, std::vector<SignatureRecord>> index;
    };

private:
    bool CaptureSnapshot(DatabaseSnapshot* snapshot, std::wstring* error_message) const;

    mutable std::mutex mutex_;
    DatabaseSnapshot database_;
};
