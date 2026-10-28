// A secure reference version: RAII ownership, bounded input, std::string and no raw new/delete
#include <array>
#include <iomanip>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

class Buffer {
public:
    explicit Buffer(std::size_t size) : data_(size, 0) {}

    std::size_t size() const { return data_.size(); }

    bool write(std::size_t offset, const std::string& text) {
        if (offset > data_.size() || text.size() > data_.size() - offset) {
            return false;
        }
        std::copy(text.begin(), text.end(), data_.begin() + offset);
        return true;
    }

private:
    std::vector<char> data_;
};

int main() {
    std::array<char, 16> name{};
    std::cin >> std::setw(static_cast<int>(name.size())) >> name.data();

    std::string line;
    if (!std::getline(std::cin, line)) {
        return 1;
    }

    auto buffer = std::make_unique<Buffer>(64);
    if (!buffer->write(0, line)) {
        std::cerr << "input too long" << std::endl;
        return 1;
    }
    std::cout << "stored " << line.size() << " bytes" << std::endl;
    return 0;
}
