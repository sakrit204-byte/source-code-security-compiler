// Inventory tool: SQL injection, dangling reference, stream overflow, leaks and a default-seeded engine
#include <iostream>
#include <string>
#include <sstream>
#include <random>
#include <sqlite3.h>

namespace inventory {

struct Item {
    int id;
    std::string name;
};

const std::string& defaultLabel() {
    std::string label = "unnamed";
    return label;                       // reference to a destroyed local
}

char* formatId(int id) {
    char buffer[16];
    snprintf(buffer, sizeof buffer, "ID-%d", id);
    return buffer;                      // address of a stack array
}

void findItem(sqlite3* db, const std::string& name) {
    std::string sql = "SELECT * FROM items WHERE name = '" + name + "';";
    char* err = nullptr;
    sqlite3_exec(db, sql.c_str(), nullptr, nullptr, &err);
}

int pickWinner(int count) {
    std::default_random_engine engine;  // default seed: the same "random" winner every run
    std::uniform_int_distribution<int> dist(0, count - 1);
    return dist(engine);
}

void importItems(std::istream& in) {
    char code[8];
    in.getline(code, 64);
    Item* item = new Item{0, code};
    std::cout << "imported " << item->name << std::endl;
}

}  // namespace inventory

int main() {
    sqlite3* db = nullptr;
    sqlite3_open("inventory.db", &db);
    std::string query;
    std::getline(std::cin, query);
    inventory::findItem(db, query);
    std::cout << inventory::formatId(7) << " " << inventory::pickWinner(10) << std::endl;
    inventory::importItems(std::cin);
    sqlite3_close(db);
    return 0;
}
