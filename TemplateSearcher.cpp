#include <iostream>
#include <Windows.h>
#include <sstream>
#include <iomanip>
#include "TemplateSearcher.h"
#include <Psapi.h>


void TemplateSearcher::init_modules() {
    // TODO: I have to think about this thing. I have to allocate some memory on the heap. This Microsoft "hacks" fuck my brain.
    HMODULE modules_handles_memory[1024];
    ModulesHandles *modules_handles = this->get_modules_handles(this->process_handle, modules_handles_memory, 1024);
    if (modules_handles == nullptr) {
        std::ostringstream exception_message;
        exception_message << "Modules have not been found" << std::endl;
        throw std::runtime_error(exception_message.str());
    }

    for (size_t i = 0; i < modules_handles->size; i++) {
        ModuleHandleWrapper *module_handle_wrapper = modules_handles->modules_handles_wrappers + i;
        std::cout << "Module #" << (i + 1) << ":" << std::endl;
        std::cout << "Its handle at 0x" << module_handle_wrapper->module_handle << std::endl;
        std::wcout << "Name: " << module_handle_wrapper->name << std::endl;
        std::cout << "Start: 0x" << std::hex << module_handle_wrapper->get_start_ptr() << std::endl;
        std::cout << "End pointer: 0x" << std::hex << module_handle_wrapper->get_end_ptr() << std::endl;
        std::cout << "Size: " << module_handle_wrapper->size << std::endl;
        std::cout << std::endl;
    }

    this->modules_handles = modules_handles;
}

ModulesHandles *
TemplateSearcher::get_modules_handles(HANDLE process_handle, HMODULE *modules_handles, size_t modules_handles_size) {
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
    size_t count_of_modules_handles = count_of_written_modules_handles / sizeof(HMODULE);
    result_modules_handles_ptr->size = count_of_modules_handles;

    ModuleHandleWrapper *modules_handles_wrapper = new ModuleHandleWrapper[result_modules_handles_ptr->size];
    for (size_t i = 0; i < result_modules_handles_ptr->size; i++) {
        HMODULE module_handle = modules_handles[i];
        WCHAR *module_name = new WCHAR[MAX_PATH];
        if (!GetModuleFileNameEx(this->process_handle, module_handle, module_name, MAX_PATH)) {
            std::cout << "Could not get module name #" << (i + 1) << " 0x" << (size_t *) module_handle << std::endl;
            continue;
        }

        MODULEINFO module_information;
        if (!GetModuleInformation(this->process_handle, module_handle, &module_information, sizeof(MODULEINFO))) {
            std::cout << "Could not get module information#" << (i + 1) << " 0x" << (size_t *) module_handle
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

void *TemplateSearcher::search(unsigned char *search_ptr, size_t length) {
    for (size_t i = 0; i < this->modules_handles->size; i++) {
        ModuleHandleWrapper *module_handle_wrapper = this->modules_handles->modules_handles_wrappers + i;

        unsigned char *read_memory_buffer = new unsigned char[module_handle_wrapper->size];
        SIZE_T count_of_read_bytes = 0;

        if (!ReadProcessMemory(this->process_handle, module_handle_wrapper->get_start_ptr(), read_memory_buffer,
                               module_handle_wrapper->size, &count_of_read_bytes)) {
            std::cout << "Could not read process memory for module #" << (i + 1) << " 0x"
                      << module_handle_wrapper->get_start_ptr() << std::endl;
            delete[] read_memory_buffer;
            continue;
        }

        std::cout << "Search for a module #";
        std::cout << std::setw(5) << std::setfill(' ') << std::left << std::dec << (i + 1);
        std::cout << " from 0x" << module_handle_wrapper->get_start_ptr() << "..." << std::endl;

        size_t template_byte_pos = 0;
        for (size_t memory_byte_pos = 0; memory_byte_pos < module_handle_wrapper->size; memory_byte_pos++) {
            // Here is no space inside the module for the pattern.
            if (length > (module_handle_wrapper->size - memory_byte_pos)) {
                // std::cout << "No space for template inside the module" << std::endl;
                break;
            }

            unsigned char current_memory_byte = read_memory_buffer[memory_byte_pos];
            if (current_memory_byte != search_ptr[template_byte_pos]) {
//                size_t *current_memory_byte_ptr = (size_t * )(
//                        (char *) module_handle_wrapper->get_start_ptr() + memory_byte_pos);
                // std::cout << "[0x" << current_memory_byte_ptr << "] Bytes are not equal (" << current_memory_byte << " != " << search_ptr[template_byte_pos] << ")" << std::endl;
                continue;
            }

            size_t *current_memory_byte_ptr = (size_t * )(
                    (char *) module_handle_wrapper->get_start_ptr() + memory_byte_pos);

            // The first byte of the pattern has been found.
            // Inside of this cycle we are checking other values of the pattern.
            template_byte_pos++;
            while (template_byte_pos != length) {
                current_memory_byte = read_memory_buffer[memory_byte_pos + template_byte_pos];
                current_memory_byte_ptr = (size_t * )(
                        (char *) module_handle_wrapper->get_start_ptr() + memory_byte_pos + template_byte_pos);
                // If bytes are not equal to each other.
                if (current_memory_byte != search_ptr[template_byte_pos]) {
                    template_byte_pos = 0;
                    break;
                }

                template_byte_pos++;
            }

            // The pattern has been found.
            if (template_byte_pos == length) {
                std::cout << "The pattern has been found!" << std::endl;
                return (void *) ((char *) module_handle_wrapper->get_start_ptr() + memory_byte_pos);
            }

        }

        delete[] read_memory_buffer;
    }

    return nullptr;
}