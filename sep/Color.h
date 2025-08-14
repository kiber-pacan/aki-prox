#ifndef COLOR_H
#define COLOR_H
#include <string>

struct  Color {
    int r{}, g{}, b{}, a{};


    static constexpr Color rgb(int r, int g, int b) {
        return {r, g, b};
    }

    static constexpr Color rgba(int r, int g, int b, int a) {
        return {r, g, b, a};
    }

    static constexpr Color hex(int hex) {
        return {hex};
    }


    static constexpr Color CONSTEXPR_RGB(int r, int g, int b) {
        return {r, g, b, true};
    }

    static constexpr Color CONSTEXPR_RGBA(int r, int g, int b, int a) {
        return {r, g, b, a, true};
    }

    static constexpr Color CONSTEXPR_HEX(int hex) {
        return {hex, true};
    }

    private:

    #pragma region Constructors

    constexpr Color(int r, int g, int b, bool is_constexpr) {
        if (is_constexpr) {
            this->r = r;
            this->g = g;
            this->b = b;
            this->a = 255;
        }
    }

    constexpr Color(int r, int g, int b, int a, bool is_constexpr) {
        this->r = r;
        this->g = g;
        this->b = b;
        this->a = a;
    }

    constexpr Color(int hex, bool is_constexpr) {
        if (is_constexpr) {
            this->r = hex >> 16;
            this->g = hex >> 8 & 0xFF;
            this->b = hex & 0xFF;
            this->a = 255;
        }
    }

    Color(int r, int g, int b) {
        this->r = r;
        this->g = g;
        this->b = b;
        this->a = 255;
    }

    Color(int r, int g, int b, int a) {
        this->r = r;
        this->g = g;
        this->b = b;
        this->a = a;
    }

    Color(int hex) {
        this->r = hex >> 16;
        this->g = hex >> 8 & 0xFF;
        this->b = hex & 0xFF;
        this->a = 255;
    }

    #pragma endregion
};

#endif //COLOR_H
