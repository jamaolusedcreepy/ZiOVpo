#pragma once

#include <windows.h>

#include <string>

class SingleInstanceGuard {
public:
    explicit SingleInstanceGuard(std::wstring app_id);
    ~SingleInstanceGuard();

    SingleInstanceGuard(const SingleInstanceGuard&) = delete;
    SingleInstanceGuard& operator=(const SingleInstanceGuard&) = delete;

    bool Acquire();

private:
    std::wstring mutex_name_;
    HANDLE mutex_ = nullptr;
};
