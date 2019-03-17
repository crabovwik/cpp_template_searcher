#pragma once

#include "pch.h"
#include <iostream>
#include <Windows.h>
#include <sstream>
#include "TemplateSearcher.h"
#include <Psapi.h>

struct ModuleHandleWrapper {
    HMODULE module_handle = nullptr;

    WCHAR *name = nullptr;
    size_t size = 0;

    inline void *get_start_ptr() {
        return (void *) this->module_handle;
    }

    void *get_end_ptr() {
        return (void *) ((char *) this->get_start_ptr() + this->size);
    }
};

struct ModulesHandles {
    size_t size = 0;
    ModuleHandleWrapper *modules_handles_wrappers = nullptr;
};

class AbstractSearcher {
public:
    explicit AbstractSearcher() = default;

    virtual ~AbstractSearcher() = default;

    virtual void *search(char *search_ptr, size_t length) = 0;
};

class TemplateSearcher : public AbstractSearcher {
protected:
    size_t process_id = 0;
    HANDLE process_handle = nullptr;
    ModulesHandles *modules_handles = nullptr;
public:
    explicit TemplateSearcher(size_t process_id) : AbstractSearcher() {
        this->process_id = process_id != NULL ? process_id : GetCurrentProcessId();
        this->process_handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, this->process_id);
        if (this->process_handle == nullptr) {
            std::ostringstream exception_message;
            exception_message << "A process with the specified process_id(" << this->process_id
                              << ") has not been found";
            throw std::runtime_error(exception_message.str());
        }

        this->init_modules();
    }

    virtual ~TemplateSearcher() = default;

    virtual void init_modules();

    virtual ModulesHandles *
    get_modules_handles(HANDLE process_handle, HMODULE *modules_handles, size_t modules_handles_size);

    virtual void *search(char *search_ptr, size_t length);
};
