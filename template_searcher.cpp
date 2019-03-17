#include <iostream>
#include <Windows.h>
#include <sstream>
#include <iomanip>
#include "TemplateSearcher.h"
#include "helper.h"

int main() {
    system("color 0A"); // Everyone wants some matrix in the life

    unsigned char *template_for_search_as_bytes = new unsigned char[4]{0xDE, 0xAD, 0xC0, 0xDE};
    size_t template_for_search_as_bytes_length = 4;

    size_t process_id = 9180;

    try {
        TemplateSearcher template_searcher = TemplateSearcher(process_id);

        void *template_found_at = template_searcher.search(template_for_search_as_bytes,
                                                           template_for_search_as_bytes_length);
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
