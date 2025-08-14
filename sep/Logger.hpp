#ifndef LOGGER_H
#define LOGGER_H

#include <string>
#include <iostream>

#include "Color.h"

// Just look at names of class and file...
class Logger {
public:
    const char* name;

    // Color for severity of log
    struct severity {
        static constexpr Color LOG = Color::CONSTEXPR_HEX(0xffffff);
        static constexpr Color WARNING = Color::CONSTEXPR_HEX(0xeed202);
        static constexpr Color ERROR = Color::CONSTEXPR_HEX(0xff1100);
        static constexpr Color SUCCESS = Color::CONSTEXPR_HEX(0x76ff00);
    };

    // I just want to create object what way because it is prettier for me
    static Logger* of(const char* name) {
        return new Logger(name);
    }

    #pragma region info
    // Main method for logging
    template<typename T>
    void info(T str, auto... args) {
        start(severity::LOG);

        log(str, args...);
    }

    template<typename T>
    void info(T str) {
        start(severity::LOG);

        log(str);
    }

    #pragma endregion


    #pragma region warn
    template<typename T>
    void warn(T str, auto... args) {
        start(severity::WARNING);

        log(str, args...);
    }

    template<typename T>
    void warn(T str) {
        start(severity::WARNING);

        log(str);
    }
    #pragma endregion


    #pragma region error
    template<typename T>
    void error(T str, auto... args) {
        start(severity::ERROR);

        log(str, args...);
    }
    template<typename T>
    void error(T str) {
        start(severity::ERROR);

        log(str);
    }
    #pragma endregion


    #pragma region success
    template<typename T>
    void success(T str, auto... args) {
        start(severity::SUCCESS);

        log(str, args...);
    }

    template<typename T>
    void success(T str) {
        start(severity::SUCCESS);

        log(str);
    }
    #pragma endregion

private:
    // Stub methods
    template<typename T>
    void log(T value, auto... args) {
        // Printing
        tempLog(value, args...);

        // Reset coloring
        std::cout << "\033[0m" << std::endl;
    }

    template<typename T>
    void log(T str) {
        // Printing
        std::cout << str;

        // Reset coloring
        std::cout << "\033[0m" << std::endl;
    }



    // Stub method for recursion
    template<typename T>
    static void tempLog(T str) {
        std::cout << "";
    }

    // Method just for printing messages
    template<typename T, typename T1>
    void tempLog(T str, T1 value, auto... args) {
        /*
         *Basically erasing and printing char by char,
         *also replacing $ with value and then doing recursion with value as args[0]
        */
        for (; *str != '\0'; ++str) {
            if (str[0] == '$' && str[1] == '{' && str[2] == '}') {
                str += 3;

                std::cout << value;

                tempLog(str, args...);

                return;
            }
            std::cout << *str;
        }
    }



    // Private constructor so ppl gonna use logger::of(name)
    Logger(const char* name) {
        this->name = name;
    }

    // Start of log (Color and name)
    void start(Color color) {
        std::cout
        << "\033[38;2;"
        << color.r << ";"
        << color.g << ";"
        << color.b << "m"
        << name << ": ";
    }
};

#endif //LOGGER_H
