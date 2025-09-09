#include <iostream>
#include <memory>
#include <string>
#include <vector>
#include <unordered_map>
#include <chrono>
#include <optional>
#include <atomic>
#include <mutex>
#include <thread>
#include <future>
#include <queue>
#include <condition_variable>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <functional>
#include <random>
#include <sqlite3.h>

// ===========================================
// CORE DATA TYPES & MODELS
// ===========================================

using PersonId = std::uint64_t;
using AccountId = std::uint64_t;
using TransactionId = std::uint64_t;
using Money = std::int64_t; // Store as cents to avoid floating point issues

enum class AccountType : std::uint8_t {
    Checking, Savings, Credit, Investment, Loan
};

enum class TransactionType : std::uint8_t {
    Debit, Credit, Transfer
};

enum class TransactionStatus : std::uint8_t {
    Pending, Completed, Failed, Cancelled
};

enum class AuthProvider : std::uint8_t {
    Plaid, Yodlee, Chase, BankOfAmerica
};

// Money utility functions
class MoneyUtils {
public:
    static Money fromDollars(double dollars) {
        return static_cast<Money>(dollars * 100.0);
    }
    
    static double toDollars(Money cents) {
        return static_cast<double>(cents) / 100.0;
    }
    
    static std::string format(Money cents) {
        double dollars = toDollars(cents);
        std::ostringstream oss;
        oss << "$" << std::fixed << std::setprecision(2) << dollars;
        return oss.str();
    }
};

// ===========================================
// DOMAIN MODELS
// ===========================================

class Person {
private:
    PersonId id_;
    std::string name_;
    std::string email_;
    std::vector<AccountId> account_ids_;
    std::chrono::system_clock::time_point created_at_;

public:
    Person(PersonId id, const std::string& name, const std::string& email = "")
        : id_(id), name_(name), email_(email), created_at_(std::chrono::system_clock::now()) {}

    // Getters
    PersonId getId() const { return id_; }
    const std::string& getName() const { return name_; }
    const std::string& getEmail() const { return email_; }
    const std::vector<AccountId>& getAccountIds() const { return account_ids_; }
    std::chrono::system_clock::time_point getCreatedAt() const { return created_at_; }

    // Account management
    void addAccount(AccountId account_id) {
        account_ids_.push_back(account_id);
    }

    void removeAccount(AccountId account_id) {
        account_ids_.erase(
            std::remove(account_ids_.begin(), account_ids_.end(), account_id),
            account_ids_.end());
    }
};

class Account {
private:
    AccountId id_;
    std::string name_;
    AccountType type_;
    Money balance_;
    PersonId owner_id_;
    std::vector<TransactionId> transaction_ids_;
    std::chrono::system_clock::time_point created_at_;
    std::chrono::system_clock::time_point last_updated_;

public:
    Account(AccountId id, const std::string& name, AccountType type, PersonId owner_id, Money initial_balance = 0)
        : id_(id), name_(name), type_(type), balance_(initial_balance), owner_id_(owner_id),
          created_at_(std::chrono::system_clock::now()), last_updated_(std::chrono::system_clock::now()) {}

    // Getters
    AccountId getId() const { return id_; }
    const std::string& getName() const { return name_; }
    AccountType getType() const { return type_; }
    Money getBalance() const { return balance_; }
    PersonId getOwnerId() const { return owner_id_; }
    const std::vector<TransactionId>& getTransactionIds() const { return transaction_ids_; }

    // Balance operations
    void updateBalance(Money amount) {
        balance_ += amount;
        last_updated_ = std::chrono::system_clock::now();
    }

    void addTransaction(TransactionId transaction_id) {
        transaction_ids_.push_back(transaction_id);
        last_updated_ = std::chrono::system_clock::now();
    }

    std::string getTypeString() const {
        switch (type_) {
            case AccountType::Checking: return "Checking";
            case AccountType::Savings: return "Savings";
            case AccountType::Credit: return "Credit";
            case AccountType::Investment: return "Investment";
            case AccountType::Loan: return "Loan";
            default: return "Unknown";
        }
    }
};

class Transaction {
private:
    TransactionId id_;
    AccountId from_account_id_;
    std::optional<AccountId> to_account_id_;
    Money amount_;
    TransactionType type_;
    TransactionStatus status_;
    std::string description_;
    std::string category_;
    std::chrono::system_clock::time_point timestamp_;
    std::optional<std::string> reference_;

public:
    Transaction(TransactionId id, AccountId from_account, Money amount, 
                TransactionType type, const std::string& description)
        : id_(id), from_account_id_(from_account), amount_(amount), type_(type),
          status_(TransactionStatus::Pending), description_(description),
          timestamp_(std::chrono::system_clock::now()) {}

    // Getters
    TransactionId getId() const { return id_; }
    AccountId getFromAccountId() const { return from_account_id_; }
    std::optional<AccountId> getToAccountId() const { return to_account_id_; }
    Money getAmount() const { return amount_; }
    TransactionType getType() const { return type_; }
    TransactionStatus getStatus() const { return status_; }
    const std::string& getDescription() const { return description_; }
    const std::string& getCategory() const { return category_; }
    std::chrono::system_clock::time_point getTimestamp() const { return timestamp_; }

    // Setters
    void setToAccount(AccountId to_account) { to_account_id_ = to_account; }
    void setStatus(TransactionStatus status) { status_ = status; }
    void setCategory(const std::string& category) { category_ = category; }
    void setReference(const std::string& reference) { reference_ = reference; }

    bool isTransfer() const {
        return type_ == TransactionType::Transfer && to_account_id_.has_value();
    }

    std::string getTypeString() const {
        switch (type_) {
            case TransactionType::Debit: return "Debit";
            case TransactionType::Credit: return "Credit";
            case TransactionType::Transfer: return "Transfer";
            default: return "Unknown";
        }
    }
};

// ===========================================
// DATABASE LAYER
// ===========================================

class SQLiteDatabase {
private:
    sqlite3* db_;
    std::mutex db_mutex_;

public:
    SQLiteDatabase() : db_(nullptr) {}

    ~SQLiteDatabase() {
        if (db_) {
            sqlite3_close(db_);
        }
    }

    bool open(const std::string& filename, const std::string& password = "") {
        std::lock_guard<std::mutex> lock(db_mutex_);
        
        int rc = sqlite3_open(filename.c_str(), &db_);
        if (rc != SQLITE_OK) {
            std::cerr << "Cannot open database: " << sqlite3_errmsg(db_) << std::endl;
            return false;
        }

        // Enable encryption if password provided (requires SQLCipher)
        if (!password.empty()) {
            std::string pragma = "PRAGMA key = '" + password + "';";
            char* error_msg = nullptr;
            rc = sqlite3_exec(db_, pragma.c_str(), nullptr, nullptr, &error_msg);
            if (rc != SQLITE_OK) {
                std::cerr << "Encryption failed: " << error_msg << std::endl;
                sqlite3_free(error_msg);
                sqlite3_close(db_);
                db_ = nullptr;
                return false;
            }
        }

        // Optimize database
        execute("PRAGMA journal_mode=WAL;");
        execute("PRAGMA foreign_keys=ON;");
        execute("PRAGMA cache_size=10000;");
        execute("PRAGMA synchronous=NORMAL;");

        return true;
    }

    bool execute(const std::string& sql) {
        std::lock_guard<std::mutex> lock(db_mutex_);
        char* error_msg = nullptr;
        int rc = sqlite3_exec(db_, sql.c_str(), nullptr, nullptr, &error_msg);
        
        if (error_msg) {
            std::cerr << "SQL error: " << error_msg << std::endl;
            sqlite3_free(error_msg);
        }
        
        return rc == SQLITE_OK;
    }

    sqlite3* get() { return db_; }
    std::mutex& getMutex() { return db_mutex_; }
};

class FinanceDatabaseManager {
private:
    SQLiteDatabase db_;

public:
    bool initialize(const std::string& db_path, const std::string& password = "") {
        if (!db_.open(db_path, password)) {
            return false;
        }
        return createTables();
    }

private:
    bool createTables() {
        const std::string create_people = R"(
            CREATE TABLE IF NOT EXISTS people (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                email TEXT,
                created_at INTEGER NOT NULL
            );
        )";

        const std::string create_accounts = R"(
            CREATE TABLE IF NOT EXISTS accounts (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                type INTEGER NOT NULL,
                balance INTEGER NOT NULL DEFAULT 0,
                owner_id INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                last_updated INTEGER NOT NULL,
                FOREIGN KEY (owner_id) REFERENCES people(id)
            );
        )";

        const std::string create_transactions = R"(
            CREATE TABLE IF NOT EXISTS transactions (
                id INTEGER PRIMARY KEY,
                from_account_id INTEGER NOT NULL,
                to_account_id INTEGER,
                amount INTEGER NOT NULL,
                type INTEGER NOT NULL,
                status INTEGER NOT NULL,
                description TEXT NOT NULL,
                category TEXT,
                reference TEXT,
                timestamp INTEGER NOT NULL,
                FOREIGN KEY (from_account_id) REFERENCES accounts(id),
                FOREIGN KEY (to_account_id) REFERENCES accounts(id)
            );
        )";

        const std::string create_indexes = R"(
            CREATE INDEX IF NOT EXISTS idx_accounts_owner ON accounts(owner_id);
            CREATE INDEX IF NOT EXISTS idx_transactions_from_account ON transactions(from_account_id);
            CREATE INDEX IF NOT EXISTS idx_transactions_timestamp ON transactions(timestamp);
        )";

        return db_.execute(create_people) && 
               db_.execute(create_accounts) && 
               db_.execute(create_transactions) &&
               db_.execute(create_indexes);
    }

public:
    bool savePerson(const Person& person) {
        std::lock_guard<std::mutex> lock(db_.getMutex());
        
        const char* sql = "INSERT OR REPLACE INTO people (id, name, email, created_at) VALUES (?, ?, ?, ?)";
        sqlite3_stmt* stmt;
        
        if (sqlite3_prepare_v2(db_.get(), sql, -1, &stmt, nullptr) != SQLITE_OK) {
            return false;
        }
        
        sqlite3_bind_int64(stmt, 1, person.getId());
        sqlite3_bind_text(stmt, 2, person.getName().c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 3, person.getEmail().c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_int64(stmt, 4, std::chrono::duration_cast<std::chrono::seconds>(
            person.getCreatedAt().time_since_epoch()).count());
        
        bool success = sqlite3_step(stmt) == SQLITE_DONE;
        sqlite3_finalize(stmt);
        return success;
    }

    bool saveAccount(const Account& account) {
        std::lock_guard<std::mutex> lock(db_.getMutex());
        
        const char* sql = "INSERT OR REPLACE INTO accounts (id, name, type, balance, owner_id, created_at, last_updated) VALUES (?, ?, ?, ?, ?, ?, ?)";
        sqlite3_stmt* stmt;
        
        if (sqlite3_prepare_v2(db_.get(), sql, -1, &stmt, nullptr) != SQLITE_OK) {
            return false;
        }
        
        sqlite3_bind_int64(stmt, 1, account.getId());
        sqlite3_bind_text(stmt, 2, account.getName().c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_int(stmt, 3, static_cast<int>(account.getType()));
        sqlite3_bind_int64(stmt, 4, account.getBalance());
        sqlite3_bind_int64(stmt, 5, account.getOwnerId());
        auto now = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        sqlite3_bind_int64(stmt, 6, now);
        sqlite3_bind_int64(stmt, 7, now);
        
        bool success = sqlite3_step(stmt) == SQLITE_DONE;
        sqlite3_finalize(stmt);
        return success;
    }

    bool saveTransaction(const Transaction& transaction) {
        std::lock_guard<std::mutex> lock(db_.getMutex());
        
        const char* sql = "INSERT OR REPLACE INTO transactions (id, from_account_id, to_account_id, amount, type, status, description, category, reference, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
        sqlite3_stmt* stmt;
        
        if (sqlite3_prepare_v2(db_.get(), sql, -1, &stmt, nullptr) != SQLITE_OK) {
            return false;
        }
        
        sqlite3_bind_int64(stmt, 1, transaction.getId());
        sqlite3_bind_int64(stmt, 2, transaction.getFromAccountId());
        
        if (transaction.getToAccountId().has_value()) {
            sqlite3_bind_int64(stmt, 3, transaction.getToAccountId().value());
        } else {
            sqlite3_bind_null(stmt, 3);
        }
        
        sqlite3_bind_int64(stmt, 4, transaction.getAmount());
        sqlite3_bind_int(stmt, 5, static_cast<int>(transaction.getType()));
        sqlite3_bind_int(stmt, 6, static_cast<int>(transaction.getStatus()));
        sqlite3_bind_text(stmt, 7, transaction.getDescription().c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 8, transaction.getCategory().c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_null(stmt, 9); // reference
        sqlite3_bind_int64(stmt, 10, std::chrono::duration_cast<std::chrono::seconds>(
            transaction.getTimestamp().time_since_epoch()).count());
        
        bool success = sqlite3_step(stmt) == SQLITE_DONE;
        sqlite3_finalize(stmt);
        return success;
    }

    std::vector<std::unique_ptr<Person>> loadAllPeople() {
        std::vector<std::unique_ptr<Person>> people;
        std::lock_guard<std::mutex> lock(db_.getMutex());
        
        const char* sql = "SELECT id, name, email FROM people";
        sqlite3_stmt* stmt;
        
        if (sqlite3_prepare_v2(db_.get(), sql, -1, &stmt, nullptr) != SQLITE_OK) {
            return people;
        }
        
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            PersonId id = sqlite3_column_int64(stmt, 0);
            std::string name = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
            std::string email = sqlite3_column_text(stmt, 2) ? 
                               reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2)) : "";
            
            people.push_back(std::make_unique<Person>(id, name, email));
        }
        
        sqlite3_finalize(stmt);
        return people;
    }

    std::vector<std::unique_ptr<Account>> loadAccountsForPerson(PersonId person_id) {
        std::vector<std::unique_ptr<Account>> accounts;
        std::lock_guard<std::mutex> lock(db_.getMutex());
        
        const char* sql = "SELECT id, name, type, balance, owner_id FROM accounts WHERE owner_id = ?";
        sqlite3_stmt* stmt;
        
        if (sqlite3_prepare_v2(db_.get(), sql, -1, &stmt, nullptr) != SQLITE_OK) {
            return accounts;
        }
        
        sqlite3_bind_int64(stmt, 1, person_id);
        
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            AccountId id = sqlite3_column_int64(stmt, 0);
            std::string name = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
            AccountType type = static_cast<AccountType>(sqlite3_column_int(stmt, 2));
            Money balance = sqlite3_column_int64(stmt, 3);
            PersonId owner_id = sqlite3_column_int64(stmt, 4);
            
            accounts.push_back(std::make_unique<Account>(id, name, type, owner_id, balance));
        }
        
        sqlite3_finalize(stmt);
        return accounts;
    }

    std::vector<std::unique_ptr<Transaction>> loadTransactionsForAccount(AccountId account_id, int limit = 100) {
        std::vector<std::unique_ptr<Transaction>> transactions;
        std::lock_guard<std::mutex> lock(db_.getMutex());
        
        const char* sql = "SELECT id, from_account_id, to_account_id, amount, type, status, description, category, timestamp FROM transactions WHERE from_account_id = ? OR to_account_id = ? ORDER BY timestamp DESC LIMIT ?";
        sqlite3_stmt* stmt;
        
        if (sqlite3_prepare_v2(db_.get(), sql, -1, &stmt, nullptr) != SQLITE_OK) {
            return transactions;
        }
        
        sqlite3_bind_int64(stmt, 1, account_id);
        sqlite3_bind_int64(stmt, 2, account_id);
        sqlite3_bind_int(stmt, 3, limit);
        
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            TransactionId id = sqlite3_column_int64(stmt, 0);
            AccountId from_account_id = sqlite3_column_int64(stmt, 1);
            Money amount = sqlite3_column_int64(stmt, 3);
            TransactionType type = static_cast<TransactionType>(sqlite3_column_int(stmt, 4));
            std::string description = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 6));
            
            auto transaction = std::make_unique<Transaction>(id, from_account_id, amount, type, description);
            
            if (sqlite3_column_type(stmt, 2) != SQLITE_NULL) {
                transaction->setToAccount(sqlite3_column_int64(stmt, 2));
            }
            
            transaction->setStatus(static_cast<TransactionStatus>(sqlite3_column_int(stmt, 5)));
            
            if (sqlite3_column_text(stmt, 7)) {
                transaction->setCategory(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 7)));
            }
            
            transactions.push_back(std::move(transaction));
        }
        
        sqlite3_finalize(stmt);
        return transactions;
    }
};

// ===========================================
// AUTHENTICATION LAYER
// ===========================================

struct AuthToken {
    std::string token;
    std::chrono::system_clock::time_point expiry;
    
    bool isValid() const {
        return std::chrono::system_clock::now() < expiry;
    }
};

class AuthStrategy {
public:
    virtual ~AuthStrategy() = default;
    virtual std::future<AuthToken> authenticate(const std::string& credentials) = 0;
    virtual std::future<std::vector<std::unique_ptr<Transaction>>> fetchTransactions(
        const AuthToken& token, AccountId account_id) = 0;
    virtual bool validateToken(const AuthToken& token) = 0;
    virtual std::string getProviderName() const = 0;
};

// Mock implementation - in real app, this would make HTTP requests
class PlaidAuthStrategy : public AuthStrategy {
public:
    std::future<AuthToken> authenticate(const std::string& credentials) override {
        return std::async(std::launch::async, [credentials]() {
            // Simulate API call delay
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
            
            // Mock successful authentication
            return AuthToken{
                "plaid_access_token_" + credentials,
                std::chrono::system_clock::now() + std::chrono::hours(1)
            };
        });
    }
    
    std::future<std::vector<std::unique_ptr<Transaction>>> fetchTransactions(
        const AuthToken& token, AccountId account_id) override {
        return std::async(std::launch::async, [token, account_id]() {
            // Simulate API call
            std::this_thread::sleep_for(std::chrono::milliseconds(1000));
            
            std::vector<std::unique_ptr<Transaction>> transactions;
            
            // Generate mock transactions
            static std::atomic<TransactionId> id_counter{1000};
            std::random_device rd;
            std::mt19937 gen(rd());
            std::uniform_real_distribution<> amount_dist(5.0, 500.0);
            
            std::vector<std::string> descriptions = {
                "Coffee Shop", "Gas Station", "Grocery Store", "Restaurant",
                "Online Purchase", "ATM Withdrawal", "Salary Deposit", "Utility Bill"
            };
            
            std::vector<std::string> categories = {
                "Food & Dining", "Transportation", "Shopping", "Bills & Utilities",
                "Income", "Entertainment", "Healthcare", "Travel"
            };
            
            for (int i = 0; i < 10; ++i) {
                Money amount = MoneyUtils::fromDollars(amount_dist(gen));
                TransactionType type = (i % 3 == 0) ? TransactionType::Credit : TransactionType::Debit;
                
                auto transaction = std::make_unique<Transaction>(
                    id_counter.fetch_add(1),
                    account_id,
                    (type == TransactionType::Debit) ? -amount : amount,
                    type,
                    descriptions[i % descriptions.size()]
                );
                
                transaction->setCategory(categories[i % categories.size()]);
                transaction->setStatus(TransactionStatus::Completed);
                
                transactions.push_back(std::move(transaction));
            }
            
            return transactions;
        });
    }
    
    bool validateToken(const AuthToken& token) override {
        return token.isValid() && token.token.find("plaid_access_token_") == 0;
    }
    
    std::string getProviderName() const override {
        return "Plaid";
    }
};

class AuthStrategyFactory {
public:
    static std::unique_ptr<AuthStrategy> createStrategy(AuthProvider provider) {
        switch (provider) {
            case AuthProvider::Plaid:
                return std::make_unique<PlaidAuthStrategy>();
            // Add other providers as needed
            default:
                throw std::invalid_argument("Unsupported auth provider");
        }
    }
};

// ===========================================
// SERVICE LAYER
// ===========================================

class FinanceService {
private:
    FinanceDatabaseManager& db_manager_;
    std::unordered_map<PersonId, std::unique_ptr<Person>> people_;
    std::unordered_map<AccountId, std::unique_ptr<Account>> accounts_;
    std::unordered_map<TransactionId, std::unique_ptr<Transaction>> transactions_;
    
    std::atomic<PersonId> next_person_id_{1};
    std::atomic<AccountId> next_account_id_{1};
    std::atomic<TransactionId> next_transaction_id_{1};
    
    std::mutex service_mutex_;

public:
    FinanceService(FinanceDatabaseManager& db) : db_manager_(db) {
        loadFromDatabase();
    }

private:
    void loadFromDatabase() {
        std::lock_guard<std::mutex> lock(service_mutex_);
        
        // Load people
        auto people_from_db = db_manager_.loadAllPeople();
        PersonId max_person_id = 0;
        
        for (auto& person : people_from_db) {
            PersonId id = person->getId();
            max_person_id = std::max(max_person_id, id);
            
            // Load accounts for this person
            auto accounts = db_manager_.loadAccountsForPerson(id);
            for (auto& account : accounts) {
                person->addAccount(account->getId());
                accounts_[account->getId()] = std::move(account);
            }
            
            people_[id] = std::move(person);
        }
        
        next_person_id_ = max_person_id + 1;
        
        // Update next account ID
        AccountId max_account_id = 0;
        for (const auto& [id, account] : accounts_) {
            max_account_id = std::max(max_account_id, id);
        }
        next_account_id_ = max_account_id + 1;
    }

public:
    PersonId createPerson(const std::string& name, const std::string& email = "") {
        std::lock_guard<std::mutex> lock(service_mutex_);
        
        PersonId id = next_person_id_.fetch_add(1);
        auto person = std::make_unique<Person>(id, name, email);
        
        db_manager_.savePerson(*person);
        people_[id] = std::move(person);
        
        return id;
    }

    AccountId createAccount(PersonId person_id, const std::string& name, 
                           AccountType type, Money initial_balance = 0) {
        std::lock_guard<std::mutex> lock(service_mutex_);
        
        auto person_it = people_.find(person_id);
        if (person_it == people_.end()) {
            throw std::runtime_error("Person not found");
        }
        
        AccountId id = next_account_id_.fetch_add(1);
        auto account = std::make_unique<Account>(id, name, type, person_id, initial_balance);
        
        person_it->second->addAccount(id);
        db_manager_.saveAccount(*account);
        accounts_[id] = std::move(account);
        
        return id;
    }

    TransactionId createTransaction(AccountId from_account_id, Money amount,
                                   TransactionType type, const std::string& description) {
        std::lock_guard<std::mutex> lock(service_mutex_);
        
        auto account_it = accounts_.find(from_account_id);
        if (account_it == accounts_.end()) {
            throw std::runtime_error("Account not found");
        }
        
        TransactionId id = next_transaction_id_.fetch_add(1);
        auto transaction = std::make_unique<Transaction>(id, from_account_id, amount, type, description);
        
        // Update account balance
        account_it->second->updateBalance(amount);
        account_it->second->addTransaction(id);
        
        db_manager_.saveTransaction(*transaction);
        db_manager_.saveAccount(*account_it->second);
        
        transactions_[id] = std::move(transaction);
        
        return id;
    }

    std::future<void> syncTransactionsFromBank(AccountId account_id, AuthProvider provider, 
                                              const std::string& credentials) {
        return std::async(std::launch::async, [this, account_id, provider, credentials]() {
            try {
                auto auth_strategy = AuthStrategyFactory::createStrategy(provider);
                
                // Authenticate
                auto token_future = auth_strategy->authenticate(credentials);
                auto token = token_future.get();
                
                if (!auth_strategy->validateToken(token)) {
                    throw std::runtime_error("Authentication failed");
                }
                
                // Fetch transactions
                auto transactions_future = auth_strategy->fetchTransactions(token, account_id);
                auto new_transactions = transactions_future.get();
                
                // Save new transactions
                std::lock_guard<std::mutex> lock(service_mutex_);
                
                auto account_it = accounts_.find(account_id);
                if (account_it == accounts_.end()) {
                    throw std::runtime_error("Account not found");
                }
                
                for (auto& transaction : new_transactions) {
                    TransactionId id = transaction->getId();
                    
                    // Update account
                    account_it->second->updateBalance(transaction->getAmount());
                    account_it->second->addTransaction(id);
                    
                    // Save to database
                    db_manager_.saveTransaction(*transaction);
                    transactions_[id] = std::move(transaction);
                }
                
                db_manager_.saveAccount(*account_it->second);
                
                std::cout << "Successfully synced " << new_transactions.size() 
                         << " transactions from " << auth_strategy->getProviderName() << std::endl;
                
            } catch (const std::exception& e) {
                std::cerr << "Sync failed: " << e.what() << std::endl;
            }
        });
    }

    // Getters
    const Person* getPerson(PersonId id) const {
        std::lock_guard<std::mutex> lock(service_mutex_);
        auto it = people_.find(id);
        return (it != people_.end()) ? it->second.get() : nullptr;
    }

    const Account* getAccount(AccountId id) const {
        std::lock_guard<std::mutex> lock(service_mutex_);
        auto it = accounts_.find(id);
        return (it != accounts_.end()) ? it->second.get() : nullptr;
    }

    const Transaction* getTransaction(TransactionId id) const {
        std::lock_guard<std::mutex> lock(service_mutex_);
        auto it = transactions_.find(id);
        return (it != transactions_.end()) ? it->second.get() : nullptr;
    }

    std::vector<const Person*> getAllPeople() const {
        std::lock_guard<std::mutex> lock(service_mutex_);
        std::vector<const Person*> result;
        for (const auto& [id, person] : people_) {
            result.push_back(person.get());
        }
        return result;
    }

    std::vector<const Account*> getAccountsForPerson(PersonId person_id) const {
        std::lock_guard<std::mutex> lock(service_mutex_);
        std::vector<const Account*> result;
        
        auto person_it = people_.find(person_id);
        if (person_it != people_.end()) {
            for (AccountId account_id : person_it->second->getAccountIds()) {
                auto account_it = accounts_.find(account_id);
                if (account_it != accounts_.end()) {
                    result.push_back(account_it->second.get());
                }
            }
        }
        return result;
    }

    std::vector<const Transaction*> getTransactionsForAccount(AccountId account_id) const {
        std::lock_guard<std::mutex> lock(service_mutex_);
        std::vector<const Transaction*> result;
        
        auto account_it = accounts_.find(account_id);
        if (account_it != accounts_.end()) {
            for (TransactionId transaction_id : account_it->second->getTransactionIds()) {
                auto transaction_it = transactions_.find(transaction_id);
                if (transaction_it != transactions_.end()) {
                    result.push_back(transaction_it->second.get());
                }
            }
        }
        
        // Sort by timestamp (most recent first)
        std::sort(result.begin(), result.end(), 
                 [](const Transaction* a, const Transaction* b) {
                     return a->getTimestamp() > b->getTimestamp();
                 });
        
        return result;
    }

    Money getTotalNetWorth(PersonId person_id) const {
        Money total = 0;
        auto accounts = getAccountsForPerson(person_id);
        
        for (const Account* account : accounts) {
            if (account->getType() == AccountType::Credit || account->getType() == AccountType::Loan) {
                total -= account->getBalance(); // Debts are negative
            } else {
                total += account->getBalance();
            }
        }
        
        return total;
    }
};

// ===========================================
// COMMAND PATTERN FOR UNDO/REDO
// ===========================================

class Command {
public:
    virtual ~Command() = default;
    virtual void execute() = 0;
    virtual void undo() = 0;
    virtual std::string getDescription() const = 0;
};

class CreateTransactionCommand : public Command {
private:
    FinanceService& service_;
    AccountId from_account_;
    Money amount_;
    TransactionType type_;
    std::string description_;
    TransactionId created_id_;
    bool executed_;

public:
    CreateTransactionCommand(FinanceService& service, AccountId from_account,
                           Money amount, TransactionType type, const std::string& description)
        : service_(service), from_account_(from_account), amount_(amount),
          type_(type), description_(description), created_id_(0), executed_(false) {}

    void execute() override {
        if (!executed_) {
            created_id_ = service_.createTransaction(from_account_, amount_, type_, description_);
            executed_ = true;
        }
    }

    void undo() override {
        if (executed_) {
            // In a real implementation, you'd add a deleteTransaction method
            // For now, we'll just mark it as cancelled
            executed_ = false;
        }
    }

    std::string getDescription() const override {
        return "Create transaction: " + description_;
    }
};

class CommandManager {
private:
    std::vector<std::unique_ptr<Command>> executed_commands_;
    size_t current_index_;
    std::mutex command_mutex_;

public:
    CommandManager() : current_index_(0) {}

    void executeCommand(std::unique_ptr<Command> command) {
        std::lock_guard<std::mutex> lock(command_mutex_);
        
        // Remove any commands after current index (for redo functionality)
        executed_commands_.erase(executed_commands_.begin() + current_index_, 
                                executed_commands_.end());

        command->execute();
        executed_commands_.push_back(std::move(command));
        current_index_ = executed_commands_.size();
    }

    bool canUndo() const {
        std::lock_guard<std::mutex> lock(command_mutex_);
        return current_index_ > 0;
    }

    bool canRedo() const {
        std::lock_guard<std::mutex> lock(command_mutex_);
        return current_index_ < executed_commands_.size();
    }

    void undo() {
        std::lock_guard<std::mutex> lock(command_mutex_);
        if (current_index_ > 0) {
            --current_index_;
            executed_commands_[current_index_]->undo();
        }
    }

    void redo() {
        std::lock_guard<std::mutex> lock(command_mutex_);
        if (current_index_ < executed_commands_.size()) {
            executed_commands_[current_index_]->execute();
            ++current_index_;
        }
    }

    std::string getLastCommandDescription() const {
        std::lock_guard<std::mutex> lock(command_mutex_);
        if (current_index_ > 0) {
            return executed_commands_[current_index_ - 1]->getDescription();
        }
        return "";
    }
};

// ===========================================
// CONSOLE UI LAYER
// ===========================================

class ConsoleUI {
private:
    FinanceService& service_;
    CommandManager command_manager_;
    
    // Helper methods for input validation
    int getIntInput(const std::string& prompt, int min_val = 0, int max_val = INT_MAX) {
        int value;
        while (true) {
            std::cout << prompt;
            if (std::cin >> value && value >= min_val && value <= max_val) {
                std::cin.ignore(); // Clear newline
                return value;
            }
            std::cout << "Invalid input. Please enter a number between " 
                     << min_val << " and " << max_val << ".\n";
            std::cin.clear();
            std::cin.ignore(10000, '\n');
        }
    }
    
    double getDoubleInput(const std::string& prompt, double min_val = 0.0) {
        double value;
        while (true) {
            std::cout << prompt;
            if (std::cin >> value && value >= min_val) {
                std::cin.ignore(); // Clear newline
                return value;
            }
            std::cout << "Invalid input. Please enter a number >= " << min_val << ".\n";
            std::cin.clear();
            std::cin.ignore(10000, '\n');
        }
    }
    
    std::string getStringInput(const std::string& prompt) {
        std::string input;
        std::cout << prompt;
        std::getline(std::cin, input);
        return input;
    }

public:
    ConsoleUI(FinanceService& service) : service_(service) {}

    void run() {
        std::cout << "=================================\n";
        std::cout << "  Personal Finance Tracker\n";
        std::cout << "=================================\n\n";

        while (true) {
            showMainMenu();
            int choice = getIntInput("Enter your choice: ", 0, 9);

            switch (choice) {
                case 1: createPersonFlow(); break;
                case 2: createAccountFlow(); break;
                case 3: createTransactionFlow(); break;
                case 4: syncBankDataFlow(); break;
                case 5: viewPeopleFlow(); break;
                case 6: viewAccountsFlow(); break;
                case 7: viewTransactionsFlow(); break;
                case 8: viewNetWorthFlow(); break;
                case 9: showCommandHistory(); break;
                case 0: 
                    std::cout << "Thank you for using Personal Finance Tracker!\n";
                    return;
                default:
                    std::cout << "Invalid choice. Please try again.\n";
            }
            
            std::cout << "\nPress Enter to continue...";
            std::cin.get();
        }
    }

private:
    void showMainMenu() {
        std::cout << "\n=== MAIN MENU ===\n";
        std::cout << "1. Create Person\n";
        std::cout << "2. Create Account\n";
        std::cout << "3. Create Transaction\n";
        std::cout << "4. Sync Bank Data\n";
        std::cout << "5. View People\n";
        std::cout << "6. View Accounts\n";
        std::cout << "7. View Transactions\n";
        std::cout << "8. View Net Worth\n";
        std::cout << "9. Command History (Undo/Redo)\n";
        std::cout << "0. Exit\n";
        std::cout << "================\n";
    }

    void createPersonFlow() {
        std::cout << "\n=== CREATE PERSON ===\n";
        std::string name = getStringInput("Enter name: ");
        std::string email = getStringInput("Enter email (optional): ");
        
        try {
            PersonId id = service_.createPerson(name, email);
            std::cout << "Person created successfully with ID: " << id << "\n";
        } catch (const std::exception& e) {
            std::cout << "Error creating person: " << e.what() << "\n";
        }
    }

    void createAccountFlow() {
        std::cout << "\n=== CREATE ACCOUNT ===\n";
        
        // Show available people
        auto people = service_.getAllPeople();
        if (people.empty()) {
            std::cout << "No people found. Please create a person first.\n";
            return;
        }
        
        std::cout << "Available people:\n";
        for (size_t i = 0; i < people.size(); ++i) {
            std::cout << i + 1 << ". " << people[i]->getName() 
                     << " (ID: " << people[i]->getId() << ")\n";
        }
        
        int person_choice = getIntInput("Select person (number): ", 1, static_cast<int>(people.size()));
        PersonId person_id = people[person_choice - 1]->getId();
        
        std::string name = getStringInput("Enter account name: ");
        
        std::cout << "Account types:\n";
        std::cout << "1. Checking\n2. Savings\n3. Credit\n4. Investment\n5. Loan\n";
        int type_choice = getIntInput("Select account type: ", 1, 5);
        AccountType type = static_cast<AccountType>(type_choice - 1);
        
        double initial_balance = getDoubleInput("Enter initial balance: $");
        Money balance = MoneyUtils::fromDollars(initial_balance);
        
        try {
            AccountId id = service_.createAccount(person_id, name, type, balance);
            std::cout << "Account created successfully with ID: " << id << "\n";
        } catch (const std::exception& e) {
            std::cout << "Error creating account: " << e.what() << "\n";
        }
    }

    void createTransactionFlow() {
        std::cout << "\n=== CREATE TRANSACTION ===\n";
        
        // Show available accounts
        auto people = service_.getAllPeople();
        if (people.empty()) {
            std::cout << "No people found. Please create a person first.\n";
            return;
        }
        
        std::vector<const Account*> all_accounts;
        for (const Person* person : people) {
            auto accounts = service_.getAccountsForPerson(person->getId());
            all_accounts.insert(all_accounts.end(), accounts.begin(), accounts.end());
        }
        
        if (all_accounts.empty()) {
            std::cout << "No accounts found. Please create an account first.\n";
            return;
        }
        
        std::cout << "Available accounts:\n";
        for (size_t i = 0; i < all_accounts.size(); ++i) {
            const Person* owner = service_.getPerson(all_accounts[i]->getOwnerId());
            std::cout << i + 1 << ". " << all_accounts[i]->getName() 
                     << " (" << all_accounts[i]->getTypeString() << ") - " 
                     << owner->getName() << " - Balance: " 
                     << MoneyUtils::format(all_accounts[i]->getBalance()) << "\n";
        }
        
        int account_choice = getIntInput("Select account (number): ", 1, static_cast<int>(all_accounts.size()));
        AccountId account_id = all_accounts[account_choice - 1]->getId();
        
        std::string description = getStringInput("Enter transaction description: ");
        
        std::cout << "Transaction types:\n";
        std::cout << "1. Debit (money out)\n2. Credit (money in)\n3. Transfer\n";
        int type_choice = getIntInput("Select transaction type: ", 1, 3);
        TransactionType type = static_cast<TransactionType>(type_choice - 1);
        
        double amount_dollars = getDoubleInput("Enter amount: $");
        Money amount = MoneyUtils::fromDollars(amount_dollars);
        
        // For debits, make amount negative
        if (type == TransactionType::Debit) {
            amount = -amount;
        }
        
        try {
            auto command = std::make_unique<CreateTransactionCommand>(
                service_, account_id, amount, type, description);
            command_manager_.executeCommand(std::move(command));
            std::cout << "Transaction created successfully!\n";
        } catch (const std::exception& e) {
            std::cout << "Error creating transaction: " << e.what() << "\n";
        }
    }

    void syncBankDataFlow() {
        std::cout << "\n=== SYNC BANK DATA ===\n";
        
        // Show available accounts
        auto people = service_.getAllPeople();
        std::vector<const Account*> all_accounts;
        for (const Person* person : people) {
            auto accounts = service_.getAccountsForPerson(person->getId());
            all_accounts.insert(all_accounts.end(), accounts.begin(), accounts.end());
        }
        
        if (all_accounts.empty()) {
            std::cout << "No accounts found. Please create an account first.\n";
            return;
        }
        
        std::cout << "Available accounts:\n";
        for (size_t i = 0; i < all_accounts.size(); ++i) {
            const Person* owner = service_.getPerson(all_accounts[i]->getOwnerId());
            std::cout << i + 1 << ". " << all_accounts[i]->getName() 
                     << " - " << owner->getName() << "\n";
        }
        
        int account_choice = getIntInput("Select account (number): ", 1, static_cast<int>(all_accounts.size()));
        AccountId account_id = all_accounts[account_choice - 1]->getId();
        
        std::cout << "Available providers:\n";
        std::cout << "1. Plaid\n2. Yodlee (not implemented)\n3. Chase (not implemented)\n4. Bank of America (not implemented)\n";
        int provider_choice = getIntInput("Select provider: ", 1, 1); // Only Plaid implemented
        
        if (provider_choice != 1) {
            std::cout << "Only Plaid is currently implemented.\n";
            return;
        }
        
        std::string credentials = getStringInput("Enter credentials (mock): ");
        
        std::cout << "Syncing data from bank... This may take a moment.\n";
        
        try {
            auto sync_future = service_.syncTransactionsFromBank(account_id, AuthProvider::Plaid, credentials);
            sync_future.wait(); // Wait for completion
            std::cout << "Bank data sync completed!\n";
        } catch (const std::exception& e) {
            std::cout << "Error syncing bank data: " << e.what() << "\n";
        }
    }

    void viewPeopleFlow() {
        std::cout << "\n=== PEOPLE ===\n";
        auto people = service_.getAllPeople();
        
        if (people.empty()) {
            std::cout << "No people found.\n";
            return;
        }
        
        for (const Person* person : people) {
            std::cout << "ID: " << person->getId() << "\n";
            std::cout << "Name: " << person->getName() << "\n";
            std::cout << "Email: " << person->getEmail() << "\n";
            
            auto accounts = service_.getAccountsForPerson(person->getId());
            std::cout << "Accounts: " << accounts.size() << "\n";
            
            Money net_worth = service_.getTotalNetWorth(person->getId());
            std::cout << "Net Worth: " << MoneyUtils::format(net_worth) << "\n";
            std::cout << "---\n";
        }
    }

    void viewAccountsFlow() {
        std::cout << "\n=== ACCOUNTS ===\n";
        auto people = service_.getAllPeople();
        
        for (const Person* person : people) {
            auto accounts = service_.getAccountsForPerson(person->getId());
            if (!accounts.empty()) {
                std::cout << person->getName() << "'s accounts:\n";
                for (const Account* account : accounts) {
                    std::cout << "  " << account->getName() 
                             << " (" << account->getTypeString() << "): "
                             << MoneyUtils::format(account->getBalance()) << "\n";
                }
                std::cout << "\n";
            }
        }
    }

    void viewTransactionsFlow() {
        std::cout << "\n=== TRANSACTIONS ===\n";
        
        // Show available accounts
        auto people = service_.getAllPeople();
        std::vector<const Account*> all_accounts;
        for (const Person* person : people) {
            auto accounts = service_.getAccountsForPerson(person->getId());
            all_accounts.insert(all_accounts.end(), accounts.begin(), accounts.end());
        }
        
        if (all_accounts.empty()) {
            std::cout << "No accounts found.\n";
            return;
        }
        
        std::cout << "Available accounts:\n";
        for (size_t i = 0; i < all_accounts.size(); ++i) {
            const Person* owner = service_.getPerson(all_accounts[i]->getOwnerId());
            std::cout << i + 1 << ". " << all_accounts[i]->getName() 
                     << " - " << owner->getName() << "\n";
        }
        
        int account_choice = getIntInput("Select account (number): ", 1, static_cast<int>(all_accounts.size()));
        AccountId account_id = all_accounts[account_choice - 1]->getId();
        
        auto transactions = service_.getTransactionsForAccount(account_id);
        
        if (transactions.empty()) {
            std::cout << "No transactions found for this account.\n";
            return;
        }
        
        std::cout << "\nTransactions:\n";
        for (const Transaction* transaction : transactions) {
            auto time_t = std::chrono::system_clock::to_time_t(transaction->getTimestamp());
            std::cout << "Date: " << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M") << "\n";
            std::cout << "Description: " << transaction->getDescription() << "\n";
            std::cout << "Amount: " << MoneyUtils::format(transaction->getAmount()) << "\n";
            std::cout << "Type: " << transaction->getTypeString() << "\n";
            std::cout << "Category: " << transaction->getCategory() << "\n";
            std::cout << "---\n";
        }
    }

    void viewNetWorthFlow() {
        std::cout << "\n=== NET WORTH ===\n";
        auto people = service_.getAllPeople();
        
        if (people.empty()) {
            std::cout << "No people found.\n";
            return;
        }
        
        Money total_net_worth = 0;
        for (const Person* person : people) {
            Money net_worth = service_.getTotalNetWorth(person->getId());
            total_net_worth += net_worth;
            
            std::cout << person->getName() << ": " << MoneyUtils::format(net_worth) << "\n";
            
            // Show breakdown by account type
            auto accounts = service_.getAccountsForPerson(person->getId());
            std::unordered_map<AccountType, Money> balances_by_type;
            
            for (const Account* account : accounts) {
                balances_by_type[account->getType()] += account->getBalance();
            }
            
            for (const auto& [type, balance] : balances_by_type) {
                std::string type_name;
                switch (type) {
                    case AccountType::Checking: type_name = "Checking"; break;
                    case AccountType::Savings: type_name = "Savings"; break;
                    case AccountType::Credit: type_name = "Credit"; break;
                    case AccountType::Investment: type_name = "Investment"; break;
                    case AccountType::Loan: type_name = "Loan"; break;
                }
                std::cout << "  " << type_name << ": " << MoneyUtils::format(balance) << "\n";
            }
            std::cout << "\n";
        }
        
        std::cout << "Total Net Worth: " << MoneyUtils::format(total_net_worth) << "\n";
    }

    void showCommandHistory() {
        std::cout << "\n=== COMMAND HISTORY ===\n";
        
        if (command_manager_.canUndo()) {
            std::cout << "Last command: " << command_manager_.getLastCommandDescription() << "\n";
            
            std::cout << "1. Undo last command\n";
            if (command_manager_.canRedo()) {
                std::cout << "2. Redo command\n";
            }
            std::cout << "0. Back to main menu\n";
            
            int choice = getIntInput("Enter choice: ", 0, 2);
            
            switch (choice) {
                case 1:
                    command_manager_.undo();
                    std::cout << "Command undone.\n";
                    break;
                case 2:
                    if (command_manager_.canRedo()) {
                        command_manager_.redo();
                        std::cout << "Command redone.\n";
                    }
                    break;
            }
        } else {
            std::cout << "No commands to undo.\n";
        }
    }
};

// ===========================================
// MAIN APPLICATION CLASS
// ===========================================

class FinanceApplication {
private:
    std::unique_ptr<FinanceDatabaseManager> db_manager_;
    std::unique_ptr<FinanceService> service_;
    std::unique_ptr<ConsoleUI> ui_;

public:
    bool initialize(const std::string& db_path, const std::string& password = "") {
        try {
            // Initialize database
            db_manager_ = std::make_unique<FinanceDatabaseManager>();
            if (!db_manager_->initialize(db_path, password)) {
                std::cerr << "Failed to initialize database\n";
                return false;
            }

            // Initialize service
            service_ = std::make_unique<FinanceService>(*db_manager_);

            // Initialize UI
            ui_ = std::make_unique<ConsoleUI>(*service_);

            return true;
        } catch (const std::exception& e) {
            std::cerr << "Initialization error: " << e.what() << std::endl;
            return false;
        }
    }

    void run() {
        if (!ui_) {
            std::cerr << "Application not properly initialized\n";
            return;
        }

        try {
            ui_->run();
        } catch (const std::exception& e) {
            std::cerr << "Runtime error: " << e.what() << std::endl;
        }
    }
};

// ===========================================
// MAIN ENTRY POINT
// ===========================================

int main(int argc, char* argv[]) {
    std::string db_path = "finance_tracker.db";
    std::string password = "";

    // Parse command line arguments
    if (argc > 1) {
        db_path = argv[1];
    }
    if (argc > 2) {
        password = argv[2];
    }

    FinanceApplication app;
    
    if (!app.initialize(db_path, password)) {
        std::cerr << "Failed to initialize application\n";
        return 1;
    }

    std::cout << "Database: " << db_path << std::endl;
    if (!password.empty()) {
        std::cout << "Encryption: Enabled\n";
    }
    std::cout << std::endl;

    app.run();
    return 0;
}