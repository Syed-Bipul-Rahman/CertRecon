// Minimal, dependency-free JSON parser (enough for API responses).
#pragma once

#include <cstdint>
#include <cstdio>
#include <map>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace json {

class Value {
public:
    enum class Type { Null, Bool, Number, String, Array, Object };

    Type type = Type::Null;
    bool b = false;
    double num = 0;
    std::string str;
    std::vector<Value> arr;
    std::map<std::string, Value> obj;

    bool is_null() const { return type == Type::Null; }
    bool is_string() const { return type == Type::String; }
    bool is_number() const { return type == Type::Number; }
    bool is_array() const { return type == Type::Array; }
    bool is_object() const { return type == Type::Object; }

    // Returns nullptr if key is missing or this is not an object.
    const Value* get(const std::string& key) const {
        if (type != Type::Object) return nullptr;
        auto it = obj.find(key);
        return it == obj.end() ? nullptr : &it->second;
    }
};

class ParseError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

class Parser {
public:
    explicit Parser(std::string_view s) : s_(s) {}

    Value parse() {
        Value v = parse_value(0);
        skip_ws();
        if (pos_ != s_.size()) fail("trailing characters");
        return v;
    }

private:
    static constexpr int kMaxDepth = 256;
    std::string_view s_;
    size_t pos_ = 0;

    [[noreturn]] void fail(const char* msg) const {
        throw ParseError(std::string("JSON parse error at offset ") +
                         std::to_string(pos_) + ": " + msg);
    }

    void skip_ws() {
        while (pos_ < s_.size() &&
               (s_[pos_] == ' ' || s_[pos_] == '\t' || s_[pos_] == '\n' || s_[pos_] == '\r'))
            ++pos_;
    }

    char peek() const { return pos_ < s_.size() ? s_[pos_] : '\0'; }

    void expect(char c) {
        if (peek() != c) fail("unexpected character");
        ++pos_;
    }

    bool consume_literal(std::string_view lit) {
        if (s_.substr(pos_, lit.size()) == lit) {
            pos_ += lit.size();
            return true;
        }
        return false;
    }

    Value parse_value(int depth) {
        if (depth > kMaxDepth) fail("nesting too deep");
        skip_ws();
        Value v;
        char c = peek();
        if (c == '{') {
            v.type = Value::Type::Object;
            ++pos_;
            skip_ws();
            if (peek() == '}') { ++pos_; return v; }
            for (;;) {
                skip_ws();
                std::string key = parse_string();
                skip_ws();
                expect(':');
                v.obj[std::move(key)] = parse_value(depth + 1);
                skip_ws();
                if (peek() == ',') { ++pos_; continue; }
                expect('}');
                break;
            }
        } else if (c == '[') {
            v.type = Value::Type::Array;
            ++pos_;
            skip_ws();
            if (peek() == ']') { ++pos_; return v; }
            for (;;) {
                v.arr.push_back(parse_value(depth + 1));
                skip_ws();
                if (peek() == ',') { ++pos_; continue; }
                expect(']');
                break;
            }
        } else if (c == '"') {
            v.type = Value::Type::String;
            v.str = parse_string();
        } else if (consume_literal("true")) {
            v.type = Value::Type::Bool; v.b = true;
        } else if (consume_literal("false")) {
            v.type = Value::Type::Bool; v.b = false;
        } else if (consume_literal("null")) {
            v.type = Value::Type::Null;
        } else if (c == '-' || (c >= '0' && c <= '9')) {
            v.type = Value::Type::Number;
            v.num = parse_number();
        } else {
            fail("unexpected token");
        }
        return v;
    }

    double parse_number() {
        size_t start = pos_;
        if (peek() == '-') ++pos_;
        while (pos_ < s_.size()) {
            char c = s_[pos_];
            if ((c >= '0' && c <= '9') || c == '.' || c == 'e' || c == 'E' || c == '+' || c == '-')
                ++pos_;
            else
                break;
        }
        std::string tmp(s_.substr(start, pos_ - start));
        try {
            return std::stod(tmp);
        } catch (...) {
            fail("invalid number");
        }
    }

    static void append_utf8(std::string& out, uint32_t cp) {
        if (cp < 0x80) {
            out += static_cast<char>(cp);
        } else if (cp < 0x800) {
            out += static_cast<char>(0xC0 | (cp >> 6));
            out += static_cast<char>(0x80 | (cp & 0x3F));
        } else if (cp < 0x10000) {
            out += static_cast<char>(0xE0 | (cp >> 12));
            out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
            out += static_cast<char>(0x80 | (cp & 0x3F));
        } else {
            out += static_cast<char>(0xF0 | (cp >> 18));
            out += static_cast<char>(0x80 | ((cp >> 12) & 0x3F));
            out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
            out += static_cast<char>(0x80 | (cp & 0x3F));
        }
    }

    uint32_t parse_hex4() {
        if (pos_ + 4 > s_.size()) fail("truncated \\u escape");
        uint32_t cp = 0;
        for (int i = 0; i < 4; ++i) {
            char c = s_[pos_++];
            cp <<= 4;
            if (c >= '0' && c <= '9') cp |= c - '0';
            else if (c >= 'a' && c <= 'f') cp |= c - 'a' + 10;
            else if (c >= 'A' && c <= 'F') cp |= c - 'A' + 10;
            else fail("invalid \\u escape");
        }
        return cp;
    }

    std::string parse_string() {
        expect('"');
        std::string out;
        for (;;) {
            if (pos_ >= s_.size()) fail("unterminated string");
            char c = s_[pos_++];
            if (c == '"') break;
            if (c != '\\') { out += c; continue; }
            if (pos_ >= s_.size()) fail("unterminated escape");
            char e = s_[pos_++];
            switch (e) {
                case '"': out += '"'; break;
                case '\\': out += '\\'; break;
                case '/': out += '/'; break;
                case 'b': out += '\b'; break;
                case 'f': out += '\f'; break;
                case 'n': out += '\n'; break;
                case 'r': out += '\r'; break;
                case 't': out += '\t'; break;
                case 'u': {
                    uint32_t cp = parse_hex4();
                    if (cp >= 0xD800 && cp <= 0xDBFF && s_.substr(pos_, 2) == "\\u") {
                        pos_ += 2;
                        uint32_t lo = parse_hex4();
                        cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                    }
                    append_utf8(out, cp);
                    break;
                }
                default: fail("invalid escape");
            }
        }
        return out;
    }
};

inline Value parse(std::string_view s) { return Parser(s).parse(); }

// Escape a string for JSON output.
inline std::string escape(std::string_view s) {
    std::string out;
    out.reserve(s.size() + 2);
    for (char c : s) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char buf[8];
                    snprintf(buf, sizeof buf, "\\u%04x", c);
                    out += buf;
                } else {
                    out += c;
                }
        }
    }
    return out;
}

}  // namespace json
