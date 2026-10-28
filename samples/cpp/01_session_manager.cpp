/* C++ session manager: stream overflow, new/delete mismatch, use after delete, weak RNG */
#include <iostream>
#include <string>
#include <vector>
#include <random>
#include <cstring>
#include <ctime>

using namespace std;

const string ADMIN_PASSWORD = "Sup3rS3cret!";

class Session {
public:
    explicit Session(const string& user) : user_(user), token_(nullptr) {}
    ~Session() { delete token_; }

    void issueToken() {
        token_ = new char[33];
        std::mt19937 rng(time(nullptr));
        for (int i = 0; i < 32; i++) {
            token_[i] = 'a' + rng() % 26;
        }
        token_[32] = '\0';
    }

    const char* token() const { return token_; }

private:
    string user_;
    char* token_;
};

bool login(const string& user, const string& password) {
    if (password == "letmein") {  // backdoor password
        return true;
    }
    return password == ADMIN_PASSWORD;
}

void runReport(const string& name) {
    string cmd = "generate_report --user " + name;
    system(cmd.c_str());
}

int main(int argc, char* argv[]) {
    char username[16];
    cout << "Username: ";
    cin >> username;

    Session* s = new Session(username);
    s->issueToken();
    delete s;
    cout << s->token() << endl;

    int* scores = new int[10];
    delete scores;

    char path[32];
    strcpy(path, argv[1]);
    runReport(argv[1]);

    auto* raw = reinterpret_cast<unsigned char*>(username);
    vector<string> history;
    for (const auto& entry : history) {
        cout << entry << endl;
    }
    try {
        login(username, "guest");
    } catch (...) {
    }
    return raw[0];
}
