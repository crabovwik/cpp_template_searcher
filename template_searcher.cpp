#include "pch.h"
#include <iostream>
#include <Windows.h>
#include <Psapi.h>
#include <sstream>
#include <Psapi.h>
#include <iomanip>

struct ModuleHandleWrapper {
    HMODULE module_handle = nullptr;

    WCHAR *name = nullptr;
    unsigned long size = 0;

    void *get_start_ptr();

    void *get_end_ptr();
};

void *ModuleHandleWrapper::get_start_ptr() {
    return (unsigned long *) this->module_handle;
}

void *ModuleHandleWrapper::get_end_ptr() {
    return (void *) ((char *) this->get_start_ptr() + this->size);
}


struct ModulesHandles {
    unsigned long size = 0;
    ModuleHandleWrapper *modules_handles_wrappers = nullptr;
};

class TemplateScanner {
protected:
    unsigned long process_id = 0;
    HANDLE process_handle = nullptr;
    ModulesHandles *modules_handles = nullptr;
public:
    explicit TemplateScanner(unsigned long process_id) {
        this->process_id = process_id != NULL ? process_id : GetCurrentProcessId();
        this->process_handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, this->process_id);
        if (this->process_handle == nullptr) {
            std::ostringstream exception_message;
            exception_message << "A process with the specified process_id(" << this->process_id
                              << ") has not been found";
            std::throw_with_nested(std::runtime_error(exception_message.str()));
        }

        HMODULE modules_handles_memory[1024];
        ModulesHandles *modules_handles = this->get_modules_handles(this->process_handle, modules_handles_memory, 1024);
        if (modules_handles == nullptr) {
            std::ostringstream exception_message;
            exception_message << "Modules have not been found" << std::endl;
            std::throw_with_nested(std::runtime_error(exception_message.str()));
        }

        for (unsigned long i = 0; i < modules_handles->size; i++) {
            ModuleHandleWrapper *module_handle_wrapper = modules_handles->modules_handles_wrappers + i;
            std::cout << "Module #" << (i + 1) << ":" << std::endl;
            std::cout << "Its handle at 0x" << module_handle_wrapper->module_handle << std::endl;
            std::wcout << "Name: " << module_handle_wrapper->name << std::endl;
            std::cout << "Start: 0x" << module_handle_wrapper->get_start_ptr() << std::endl;
            std::cout << "End pointer: 0x" << module_handle_wrapper->get_end_ptr() << std::endl;
            std::cout << "Size: " << module_handle_wrapper->size << std::endl;
            std::cout << std::endl;
        }

        this->modules_handles = modules_handles;
    }

    ModulesHandles *
    get_modules_handles(HANDLE process_handle, HMODULE *modules_handles, unsigned long modules_handles_size) {
        ModulesHandles *result_modules_handles_ptr = nullptr;

        // HMODULE modules_handles[1024];
        // HMODULE *modules_handles = new HMODULE[1024];
        // HMODULE *modules_handles = (HMODULE *) calloc(1024, sizeof(HMODULE));
        DWORD count_of_written_modules_handles = 0;
        if (!EnumProcessModules(this->process_handle, modules_handles, modules_handles_size,
                                &count_of_written_modules_handles)) {
            return result_modules_handles_ptr;
        }

        result_modules_handles_ptr = new ModulesHandles();
        unsigned long count_of_modules_handles = count_of_written_modules_handles / sizeof(HMODULE);
        result_modules_handles_ptr->size = count_of_modules_handles;

        ModuleHandleWrapper *modules_handles_wrapper = new ModuleHandleWrapper[result_modules_handles_ptr->size];
        for (unsigned long i = 0; i < result_modules_handles_ptr->size; i++) {
            HMODULE module_handle = modules_handles[i];
            WCHAR *module_name = new WCHAR[MAX_PATH];
            if (!GetModuleFileNameEx(this->process_handle, module_handle, module_name, MAX_PATH)) {
                std::cout << "Could not get module name #" << (i + 1) << " 0x" << (unsigned long *) module_handle
                          << std::endl;
                continue;
            }

            MODULEINFO module_information;
            if (!GetModuleInformation(this->process_handle, module_handle, &module_information, sizeof(MODULEINFO))) {
                std::cout << "Could not get module information#" << (i + 1) << " 0x" << (unsigned long *) module_handle
                          << std::endl;
                continue;
            }

            ModuleHandleWrapper *module_handle_wrapper = modules_handles_wrapper + i;
            module_handle_wrapper->module_handle = modules_handles[i];
            module_handle_wrapper->name = module_name;
            module_handle_wrapper->size = module_information.SizeOfImage;
        }

        result_modules_handles_ptr->modules_handles_wrappers = modules_handles_wrapper;

        return result_modules_handles_ptr;
    }

    void *search(char *template_for_search) {
        unsigned long template_length_as_string = strlen(template_for_search);
        if (template_length_as_string == 0 || template_length_as_string % 2 != 0) {
            std::cout << "An Incorrect template for search: " << template_for_search << std::endl;
            return nullptr;
        }

        unsigned long template_length_as_bytes = template_length_as_string / 2;

        system("color 0A"); // Everyone wants some matrix in the life
        for (unsigned long i = 0; i < this->modules_handles->size; i++) {
            ModuleHandleWrapper *module_handle_wrapper = this->modules_handles->modules_handles_wrappers + i;

            CHAR *read_memory_buffer = new CHAR[module_handle_wrapper->size];
            SIZE_T count_of_read_bytes = 0;
            if (!ReadProcessMemory(this->process_handle, module_handle_wrapper->get_start_ptr(), read_memory_buffer,
                                   module_handle_wrapper->size, &count_of_read_bytes)) {
                std::cout << "Could not read process memory for module #" << (i + 1) << " 0x"
                          << module_handle_wrapper->get_start_ptr() << std::endl;
                delete[] read_memory_buffer;
                continue;
            }

            // TODO: Search
            std::cout << "A dump of a memory block of module #" << (i + 1) << " 0x"
                      << module_handle_wrapper->get_start_ptr() << ":" << std::endl;
            for (unsigned long j = 0; j < module_handle_wrapper->size; j++) {
                BYTE current_byte = (BYTE) read_memory_buffer[j];

                std::cout << std::hex << std::setfill('0') << std::setw(2) << (int) current_byte << " ";
                if ((j + 1) % 32 == 0) {
                    std::cout << std::endl;
                }
            }

            std::cout << std::endl;

            delete[] read_memory_buffer;
        }

        return nullptr;
    }
};

int main() {
    char *template_for_search = (char *) "AABBCCDDEEFF";
    std::cout << "The template for a search: " << template_for_search << std::endl;

    unsigned long process_id = 21900;
    try {
        TemplateScanner template_scanner = TemplateScanner(process_id);

        void *template_found_at = template_scanner.search(template_for_search);
        if (template_found_at == nullptr) {
            std::cout << "The template has not been found" << std::endl;
            return 1;
        }

        std::cout << "The template has been found at: 0x" << template_found_at << std::endl;
    } catch (const std::exception &exception) {
        std::cout << "An exception has been caught: " << exception.what() << std::endl;
    }

    return 0;
}
