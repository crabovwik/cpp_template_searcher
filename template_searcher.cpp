#include "pch.h"
#include <iostream>
#include <Windows.h>
#include <sstream>
#include <iomanip>
#include "TemplateSearcher.h"
#include "helper.h"

int main() {
    system("color 0A"); // Everyone wants some matrix in the life

    char *template_for_search_as_string = (char *) "450067006F0072006900630068002C0020007A0061006500620061006C002C0020006E006100680075007900610020007400690020006D0065006E006900610020006E0061007300680065006C003F00200059006100200074007500740020006F007400640069006800610079007500290029";
    std::cout << "The template for a search: " << template_for_search_as_string << std::endl;

    size_t template_for_search_as_string_length = strlen(template_for_search_as_string);
    if (template_for_search_as_string_length % 2 != 0) {
        std::cout << "An incorrect length of the template" << std::endl;
        return 1;
    }

    size_t template_for_search_as_bytes_length = template_for_search_as_string_length / 2;
    char *template_for_search_as_bytes = new char[template_for_search_as_bytes_length];
    hex2bin(template_for_search_as_string, template_for_search_as_bytes);

    // TODO: Change a code above
    delete[] template_for_search_as_bytes;
    template_for_search_as_bytes = new char[4]{0xDE, 0xAD, 0xC0, 0xDE};
    template_for_search_as_bytes_length = 4;

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
