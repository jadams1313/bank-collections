#include <QApplication>
#include <QMainWindow>
#include <QWidget>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGridLayout>
#include <QLabel>
#include <QPushButton>
#include <QLineEdit>
#include <QComboBox>
#include <QTableWidget>
#include <QHeaderView>
#include <QMessageBox>
#include <QDialog>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QGroupBox>
#include <QSplitter>
#include <QTreeWidget>
#include <QProgressDialog>
#include <QMenuBar>
#include <QMenu>
#include <QAction>
#include <QStatusBar>
#include <QDateTime>
#include <QDoubleSpinBox>
#include <QTextEdit>
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
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <functional>
#include <random>
#include <QSqlDatabase>
#include <QSqlQuery>
#include <QSqlError>
#include <QVariant>
#include <QDebug>


using PersonId = std::uint64_t;
using AccountId = std::uint64_t;
using TransactionId = std::uint64_t;
using Money = std::int64_t;

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
    
    static QString format(Money cents) {
        double dollars = toDollars(cents);
        return QString::asprintf("$%.2f", dollars);
    }
};

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

    PersonId getId() const { return id_; }
    const std::string& getName() const { return name_; }
    const std::string& getEmail() const { return email_; }
    const std::vector<AccountId>& getAccountIds() const { return account_ids_; }
    std::chrono::system_clock::time_point getCreatedAt() const { return created_at_; }

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

    AccountId getId() const { return id_; }
    const std::string& getName() const { return name_; }
    AccountType getType() const { return type_; }
    Money getBalance() const { return balance_; }
    PersonId getOwnerId() const { return owner_id_; }
    const std::vector<TransactionId>& getTransactionIds() const { return transaction_ids_; }

    void updateBalance(Money amount) {
        balance_ += amount;
        last_updated_ = std::chrono::system_clock::now();
    }

    void addTransaction(TransactionId transaction_id) {
        transaction_ids_.push_back(transaction_id);
        last_updated_ = std::chrono::system_clock::now();
    }

    QString getTypeString() const {
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

    TransactionId getId() const { return id_; }
    AccountId getFromAccountId() const { return from_account_id_; }
    std::optional<AccountId> getToAccountId() const { return to_account_id_; }
    Money getAmount() const { return amount_; }
    TransactionType getType() const { return type_; }
    TransactionStatus getStatus() const { return status_; }
    const std::string& getDescription() const { return description_; }
    const std::string& getCategory() const { return category_; }
    std::chrono::system_clock::time_point getTimestamp() const { return timestamp_; }

    void setToAccount(AccountId to_account) { to_account_id_ = to_account; }
    void setStatus(TransactionStatus status) { status_ = status; }
    void setCategory(const std::string& category) { category_ = category; }
    void setReference(const std::string& reference) { reference_ = reference; }

    bool isTransfer() const {
        return type_ == TransactionType::Transfer && to_account_id_.has_value();
    }

    QString getTypeString() const {
        switch (type_) {
            case TransactionType::Debit: return "Debit";
            case TransactionType::Credit: return "Credit";
            case TransactionType::Transfer: return "Transfer";
            default: return "Unknown";
        }
    }
};

class FinanceDatabaseManager {
private:
    QSqlDatabase db_;

public:
    bool initialize(const QString& db_path) {
        db_ = QSqlDatabase::addDatabase("QSQLITE");
        db_.setDatabaseName(db_path);
        if (!db_.open()) {
            qWarning() << "Failed to open database:" << db_.lastError().text();
            return false;
        }
        return createTables();
    }

    bool isOpen() const {
        return db_.isOpen();
    }

private:
    bool createTables() {
        QSqlQuery query;
        bool success = true;

        success &= query.exec(R"(
            CREATE TABLE IF NOT EXISTS people (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                email TEXT,
                created_at INTEGER NOT NULL
            );
        )");

        success &= query.exec(R"(
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
        )");

        success &= query.exec(R"(
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
        )");

        if (!success) {
            qWarning() << "Error creating tables:" << query.lastError().text();
        }
        return success;
    }

public:
    bool savePerson(const Person& person) {
        QSqlQuery query;
        query.prepare("INSERT OR REPLACE INTO people (id, name, email, created_at) VALUES (?, ?, ?, ?)");
        query.addBindValue(static_cast<qint64>(person.getId()));
        query.addBindValue(QString::fromStdString(person.getName()));
        query.addBindValue(QString::fromStdString(person.getEmail()));
        query.addBindValue(static_cast<qint64>(
            std::chrono::duration_cast<std::chrono::seconds>(
                person.getCreatedAt().time_since_epoch()).count()));
        return query.exec();
    }

    bool saveAccount(const Account& account) {
        QSqlQuery query;
        query.prepare(R"(
            INSERT OR REPLACE INTO accounts
            (id, name, type, balance, owner_id, created_at, last_updated)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        )");

        const auto now = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();

        query.addBindValue(static_cast<qint64>(account.getId()));
        query.addBindValue(QString::fromStdString(account.getName()));
        query.addBindValue(static_cast<int>(account.getType()));
        query.addBindValue(static_cast<qint64>(account.getBalance()));
        query.addBindValue(static_cast<qint64>(account.getOwnerId()));
        query.addBindValue(static_cast<qint64>(now));
        query.addBindValue(static_cast<qint64>(now));

        if (!query.exec()) {
            qWarning() << "Error saving account:" << query.lastError().text();
            return false;
        }
        return true;
    }

    bool saveTransaction(const Transaction& transaction) {
        QSqlQuery query;
        query.prepare(R"(
            INSERT OR REPLACE INTO transactions
            (id, from_account_id, to_account_id, amount, type, status, description, category, reference, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        )");

        query.addBindValue(static_cast<qint64>(transaction.getId()));
        query.addBindValue(static_cast<qint64>(transaction.getFromAccountId()));

        if (transaction.getToAccountId().has_value())
            query.addBindValue(static_cast<qint64>(transaction.getToAccountId().value()));
        else
            query.addBindValue(QVariant(QVariant::Int)); // NULL

        query.addBindValue(static_cast<qint64>(transaction.getAmount()));
        query.addBindValue(static_cast<int>(transaction.getType()));
        query.addBindValue(static_cast<int>(transaction.getStatus()));
        query.addBindValue(QString::fromStdString(transaction.getDescription()));
        query.addBindValue(QString::fromStdString(transaction.getCategory()));
        query.addBindValue(QVariant(QVariant::String)); // reference = NULL for now
        query.addBindValue(static_cast<qint64>(
            std::chrono::duration_cast<std::chrono::seconds>(
                transaction.getTimestamp().time_since_epoch()).count()));

        if (!query.exec()) {
            qWarning() << "Error saving transaction:" << query.lastError().text();
            return false;
        }
        return true;
    }

    std::vector<std::unique_ptr<Person>> loadAllPeople() {
        std::vector<std::unique_ptr<Person>> people;
        QSqlQuery query("SELECT id, name, email FROM people");

        while (query.next()) {
            PersonId id = query.value(0).toULongLong();
            std::string name = query.value(1).toString().toStdString();
            std::string email = query.value(2).toString().toStdString();
            people.push_back(std::make_unique<Person>(id, name, email));
        }
        return people;
    }

    std::vector<std::unique_ptr<Account>> loadAccountsForPerson(PersonId person_id) {
        std::vector<std::unique_ptr<Account>> accounts;
        QSqlQuery query;
        query.prepare("SELECT id, name, type, balance, owner_id FROM accounts WHERE owner_id = ?");
        query.addBindValue(static_cast<qint64>(person_id));

        if (!query.exec()) {
            qWarning() << "Error loading accounts:" << query.lastError().text();
            return accounts;
        }

        while (query.next()) {
            AccountId id = query.value(0).toULongLong();
            std::string name = query.value(1).toString().toStdString();
            AccountType type = static_cast<AccountType>(query.value(2).toInt());
            Money balance = query.value(3).toLongLong();
            PersonId owner_id = query.value(4).toULongLong();

            accounts.push_back(std::make_unique<Account>(id, name, type, owner_id, balance));
        }
        return accounts;
    }
};

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

class PlaidAuthStrategy : public AuthStrategy {
public:
    std::future<AuthToken> authenticate(const std::string& credentials) override {
        return std::async(std::launch::async, [credentials]() {
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
            return AuthToken{
    "plaid_access_token_" + credentials,
    std::chrono::system_clock::now() + std::chrono::hours(1)
};
        });
    }
    
    std::future<std::vector<std::unique_ptr<Transaction>>> fetchTransactions(
        const AuthToken& token, AccountId account_id) override {
        return std::async(std::launch::async, [token, account_id]() {
            std::this_thread::sleep_for(std::chrono::milliseconds(1000));
            
            std::vector<std::unique_ptr<Transaction>> transactions;
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

class FinanceService : public QObject {
    Q_OBJECT

private:
    FinanceDatabaseManager& db_manager_;
    std::unordered_map<PersonId, std::unique_ptr<Person>> people_;
    std::unordered_map<AccountId, std::unique_ptr<Account>> accounts_;
    std::unordered_map<TransactionId, std::unique_ptr<Transaction>> transactions_;
    
    std::atomic<PersonId> next_person_id_{1};
    std::atomic<AccountId> next_account_id_{1};
    std::atomic<TransactionId> next_transaction_id_{1};
    
    mutable std::mutex service_mutex_;

public:
    FinanceService(FinanceDatabaseManager& db, QObject* parent = nullptr) 
        : QObject(parent), db_manager_(db) {
        loadFromDatabase();
    }

signals:
    void dataChanged();
    void personAdded(PersonId id);
    void accountAdded(AccountId id);
    void transactionAdded(TransactionId id);
    void syncCompleted(int count);

private:
    void loadFromDatabase() {
        std::lock_guard<std::mutex> lock(service_mutex_);
        
        auto people_from_db = db_manager_.loadAllPeople();
        PersonId max_person_id = 0;
        
        for (auto& person : people_from_db) {
            PersonId id = person->getId();
            max_person_id = std::max(max_person_id, id);
            
            auto accounts = db_manager_.loadAccountsForPerson(id);
            for (auto& account : accounts) {
                person->addAccount(account->getId());
                accounts_[account->getId()] = std::move(account);
            }
            
            people_[id] = std::move(person);
        }
        
        next_person_id_ = max_person_id + 1;
        
        AccountId max_account_id = 0;
        for (const auto& [id, account] : accounts_) {
            max_account_id = std::max(max_account_id, id);
        }
        next_account_id_ = max_account_id + 1;
    }

public:
    PersonId createPerson(const QString& name, const QString& email = "") {
        std::lock_guard<std::mutex> lock(service_mutex_);
        
        PersonId id = next_person_id_.fetch_add(1);
        auto person = std::make_unique<Person>(id, name.toStdString(), email.toStdString());
        
        db_manager_.savePerson(*person);
        people_[id] = std::move(person);
        
        emit personAdded(id);
        emit dataChanged();
        return id;
    }

    AccountId createAccount(PersonId person_id, const QString& name, 
                           AccountType type, Money initial_balance = 0) {
        std::lock_guard<std::mutex> lock(service_mutex_);
        
        auto person_it = people_.find(person_id);
        if (person_it == people_.end()) {
            throw std::runtime_error("Person not found");
        }
        
        AccountId id = next_account_id_.fetch_add(1);
        auto account = std::make_unique<Account>(id, name.toStdString(), type, person_id, initial_balance);
        
        person_it->second->addAccount(id);
        db_manager_.saveAccount(*account);
        accounts_[id] = std::move(account);
        
        emit accountAdded(id);
        emit dataChanged();
        return id;
    }

    TransactionId createTransaction(AccountId from_account_id, Money amount,
                                   TransactionType type, const QString& description) {
        std::lock_guard<std::mutex> lock(service_mutex_);
        
        auto account_it = accounts_.find(from_account_id);
        if (account_it == accounts_.end()) {
            throw std::runtime_error("Account not found");
        }
        
        TransactionId id = next_transaction_id_.fetch_add(1);
        auto transaction = std::make_unique<Transaction>(id, from_account_id, amount, type, description.toStdString());
        
        account_it->second->updateBalance(amount);
        account_it->second->addTransaction(id);
        
        db_manager_.saveTransaction(*transaction);
        db_manager_.saveAccount(*account_it->second);
        
        transactions_[id] = std::move(transaction);
        
        emit transactionAdded(id);
        emit dataChanged();
        return id;
    }

    void syncTransactionsFromBank(AccountId account_id, const QString& credentials) {
        std::thread([this, account_id, credentials]() {
            try {
                auto auth_strategy = std::make_unique<PlaidAuthStrategy>();
                auto token_future = auth_strategy->authenticate(credentials.toStdString());
                auto token = token_future.get();
                
                if (!auth_strategy->validateToken(token)) {
                    return;
                }
                
                auto transactions_future = auth_strategy->fetchTransactions(token, account_id);
                auto new_transactions = transactions_future.get();
                
                {
                    std::lock_guard<std::mutex> lock(service_mutex_);
                    
                    auto account_it = accounts_.find(account_id);
                    if (account_it == accounts_.end()) {
                        return;
                    }
                    
                    for (auto& transaction : new_transactions) {
                        TransactionId id = transaction->getId();
                        account_it->second->updateBalance(transaction->getAmount());
                        account_it->second->addTransaction(id);
                        db_manager_.saveTransaction(*transaction);
                        transactions_[id] = std::move(transaction);
                    }
                    
                    db_manager_.saveAccount(*account_it->second);
                    emit syncCompleted(new_transactions.size());
                    emit dataChanged();
                }
                
            } catch (const std::exception& e) {
                // Handle error need impl.
            }
        }).detach();
    }

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
                total -= account->getBalance();
            } else {
                total += account->getBalance();
            }
        }
        
        return total;
    }
};

class CreatePersonDialog : public QDialog {
    Q_OBJECT

private:
    QLineEdit* nameEdit;
    QLineEdit* emailEdit;

public:
    CreatePersonDialog(QWidget* parent = nullptr) : QDialog(parent) {
        setWindowTitle("Create Person");
        setModal(true);
        
        QFormLayout* layout = new QFormLayout(this);
        
        nameEdit = new QLineEdit(this);
        emailEdit = new QLineEdit(this);
        
        layout->addRow("Name:", nameEdit);
        layout->addRow("Email:", emailEdit);
        
        QDialogButtonBox* buttonBox = new QDialogButtonBox(
            QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this);
        
        connect(buttonBox, &QDialogButtonBox::accepted, this, &QDialog::accept);
        connect(buttonBox, &QDialogButtonBox::rejected, this, &QDialog::reject);
        
        layout->addRow(buttonBox);
    }

    QString getName() const { return nameEdit->text(); }
    QString getEmail() const { return emailEdit->text(); }
};

class CreateAccountDialog : public QDialog {
    Q_OBJECT

private:
    QComboBox* personCombo;
    QLineEdit* nameEdit;
    QComboBox* typeCombo;
    QDoubleSpinBox* balanceSpinBox;
    std::vector<PersonId> personIds;

public:
    CreateAccountDialog(const std::vector<const Person*>& people, QWidget* parent = nullptr) 
        : QDialog(parent) {
        setWindowTitle("Create Account");
        setModal(true);
        
        QFormLayout* layout = new QFormLayout(this);
        
        personCombo = new QComboBox(this);
        for (const Person* person : people) {
            personCombo->addItem(QString::fromStdString(person->getName()));
            personIds.push_back(person->getId());
        }
        
        nameEdit = new QLineEdit(this);
        
        typeCombo = new QComboBox(this);
        typeCombo->addItem("Checking");
        typeCombo->addItem("Savings");
        typeCombo->addItem("Credit");
        typeCombo->addItem("Investment");
        typeCombo->addItem("Loan");
        
        balanceSpinBox = new QDoubleSpinBox(this);
        balanceSpinBox->setRange(-1000000, 1000000);
        balanceSpinBox->setDecimals(2);
        balanceSpinBox->setPrefix("$");
        balanceSpinBox->setValue(0.0);
        
        layout->addRow("Owner:", personCombo);
        layout->addRow("Account Name:", nameEdit);
        layout->addRow("Account Type:", typeCombo);
        layout->addRow("Initial Balance:", balanceSpinBox);
        
        QDialogButtonBox* buttonBox = new QDialogButtonBox(
            QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this);
        
        connect(buttonBox, &QDialogButtonBox::accepted, this, &QDialog::accept);
        connect(buttonBox, &QDialogButtonBox::rejected, this, &QDialog::reject);
        
        layout->addRow(buttonBox);
    }

    PersonId getPersonId() const { 
        return personIds[personCombo->currentIndex()]; 
    }
    QString getName() const { return nameEdit->text(); }
    AccountType getType() const { 
        return static_cast<AccountType>(typeCombo->currentIndex()); 
    }
    double getBalance() const { return balanceSpinBox->value(); }
};

class CreateTransactionDialog : public QDialog {
    Q_OBJECT

private:
    QComboBox* accountCombo;
    QLineEdit* descriptionEdit;
    QComboBox* typeCombo;
    QDoubleSpinBox* amountSpinBox;
    std::vector<AccountId> accountIds;

public:
    CreateTransactionDialog(const std::vector<const Account*>& accounts, 
                           FinanceService& service, QWidget* parent = nullptr) 
        : QDialog(parent) {
        setWindowTitle("Create Transaction");
        setModal(true);
        
        QFormLayout* layout = new QFormLayout(this);
        
        accountCombo = new QComboBox(this);
        for (const Account* account : accounts) {
            const Person* owner = service.getPerson(account->getOwnerId());
            QString label = QString::fromStdString(account->getName()) + 
                          " (" + account->getTypeString() + ") - " +
                          QString::fromStdString(owner->getName());
            accountCombo->addItem(label);
            accountIds.push_back(account->getId());
        }
        
        descriptionEdit = new QLineEdit(this);
        
        typeCombo = new QComboBox(this);
        typeCombo->addItem("Debit (Money Out)");
        typeCombo->addItem("Credit (Money In)");
        typeCombo->addItem("Transfer");
        
        amountSpinBox = new QDoubleSpinBox(this);
        amountSpinBox->setRange(0, 1000000);
        amountSpinBox->setDecimals(2);
        amountSpinBox->setPrefix("$");
        amountSpinBox->setValue(0.0);
        
        layout->addRow("Account:", accountCombo);
        layout->addRow("Description:", descriptionEdit);
        layout->addRow("Type:", typeCombo);
        layout->addRow("Amount:", amountSpinBox);
        
        QDialogButtonBox* buttonBox = new QDialogButtonBox(
            QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this);
        
        connect(buttonBox, &QDialogButtonBox::accepted, this, &QDialog::accept);
        connect(buttonBox, &QDialogButtonBox::rejected, this, &QDialog::reject);
        
        layout->addRow(buttonBox);
    }

    AccountId getAccountId() const { 
        return accountIds[accountCombo->currentIndex()]; 
    }
    QString getDescription() const { return descriptionEdit->text(); }
    TransactionType getType() const { 
        return static_cast<TransactionType>(typeCombo->currentIndex()); 
    }
    double getAmount() const { return amountSpinBox->value(); }
};

class SyncBankDialog : public QDialog {
    Q_OBJECT

private:
    QComboBox* accountCombo;
    QLineEdit* credentialsEdit;
    std::vector<AccountId> accountIds;

public:
    SyncBankDialog(const std::vector<const Account*>& accounts, 
                   FinanceService& service, QWidget* parent = nullptr) 
        : QDialog(parent) {
        setWindowTitle("Sync Bank Data");
        setModal(true);
        
        QFormLayout* layout = new QFormLayout(this);
        
        accountCombo = new QComboBox(this);
        for (const Account* account : accounts) {
            const Person* owner = service.getPerson(account->getOwnerId());
            QString label = QString::fromStdString(account->getName()) + " - " +
                          QString::fromStdString(owner->getName());
            accountCombo->addItem(label);
            accountIds.push_back(account->getId());
        }
        
        credentialsEdit = new QLineEdit(this);
        credentialsEdit->setPlaceholderText("Enter mock credentials");
        
        layout->addRow("Account:", accountCombo);
        layout->addRow("Credentials:", credentialsEdit);
        
        QLabel* noteLabel = new QLabel("Note: This is a mock implementation using Plaid simulation.");
        noteLabel->setWordWrap(true);
        noteLabel->setStyleSheet("QLabel { color: gray; font-style: italic; }");
        layout->addRow(noteLabel);
        
        QDialogButtonBox* buttonBox = new QDialogButtonBox(
            QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this);
        
        connect(buttonBox, &QDialogButtonBox::accepted, this, &QDialog::accept);
        connect(buttonBox, &QDialogButtonBox::rejected, this, &QDialog::reject);
        
        layout->addRow(buttonBox);
    }

    AccountId getAccountId() const { 
        return accountIds[accountCombo->currentIndex()]; 
    }
    QString getCredentials() const { return credentialsEdit->text(); }
};



class MainWindow : public QMainWindow {
    Q_OBJECT

private:
    FinanceService* service_;
    
    // Widgets
    QTreeWidget* peopleTree;
    QTableWidget* transactionsTable;
    QLabel* netWorthLabel;
    QLabel* statusLabel;

public:
    MainWindow(FinanceService* service, QWidget* parent = nullptr) 
        : QMainWindow(parent), service_(service) {
        
        setWindowTitle("Personal Finance Tracker");
        resize(1200, 700);
        
        setupMenuBar();
        setupUI();
        setupConnections();
        refreshData();
        
        statusBar()->showMessage("Ready");
    }

private:
    void setupMenuBar() {
        QMenu* fileMenu = menuBar()->addMenu("&File");
        
        QAction* exitAction = new QAction("E&xit", this);
        exitAction->setShortcut(QKeySequence::Quit);
        connect(exitAction, &QAction::triggered, this, &QMainWindow::close);
        fileMenu->addAction(exitAction);
        
        QMenu* personMenu = menuBar()->addMenu("&Person");
        
        QAction* createPersonAction = new QAction("&Create Person", this);
        connect(createPersonAction, &QAction::triggered, this, &MainWindow::onCreatePerson);
        personMenu->addAction(createPersonAction);
        
        QMenu* accountMenu = menuBar()->addMenu("&Account");
        
        QAction* createAccountAction = new QAction("&Create Account", this);
        connect(createAccountAction, &QAction::triggered, this, &MainWindow::onCreateAccount);
        accountMenu->addAction(createAccountAction);
        
        QMenu* transactionMenu = menuBar()->addMenu("&Transaction");
        
        QAction* createTransactionAction = new QAction("&Create Transaction", this);
        connect(createTransactionAction, &QAction::triggered, this, &MainWindow::onCreateTransaction);
        transactionMenu->addAction(createTransactionAction);
        
        transactionMenu->addSeparator();
        
        QAction* syncBankAction = new QAction("&Sync Bank Data", this);
        connect(syncBankAction, &QAction::triggered, this, &MainWindow::onSyncBank);
        transactionMenu->addAction(syncBankAction);
        
        QMenu* viewMenu = menuBar()->addMenu("&View");
        
        QAction* refreshAction = new QAction("&Refresh", this);
        refreshAction->setShortcut(QKeySequence::Refresh);
        connect(refreshAction, &QAction::triggered, this, &MainWindow::refreshData);
        viewMenu->addAction(refreshAction);
    }

    void setupUI() {
        QWidget* centralWidget = new QWidget(this);
        QVBoxLayout* mainLayout = new QVBoxLayout(centralWidget);
        
        // Top section: Net Worth Display
        QGroupBox* netWorthGroup = new QGroupBox("Net Worth Summary", this);
        QHBoxLayout* netWorthLayout = new QHBoxLayout(netWorthGroup);
        
        netWorthLabel = new QLabel("Total Net Worth: $0.00", this);
        QFont font = netWorthLabel->font();
        font.setPointSize(16);
        font.setBold(true);
        netWorthLabel->setFont(font);
        netWorthLabel->setStyleSheet("QLabel { color: #2E7D32; }");
        
        netWorthLayout->addWidget(netWorthLabel);
        netWorthLayout->addStretch();
        
        mainLayout->addWidget(netWorthGroup);
        
        // Middle section: Splitter with people/accounts and transactions
        QSplitter* splitter = new QSplitter(Qt::Horizontal, this);
        
        // Left side: People and Accounts Tree
        QWidget* leftWidget = new QWidget(this);
        QVBoxLayout* leftLayout = new QVBoxLayout(leftWidget);
        
        QLabel* peopleLabel = new QLabel("People & Accounts", this);
        font = peopleLabel->font();
        font.setBold(true);
        peopleLabel->setFont(font);
        leftLayout->addWidget(peopleLabel);
        
        peopleTree = new QTreeWidget(this);
        peopleTree->setHeaderLabels({"Name", "Balance"});
        peopleTree->setColumnWidth(0, 250);
        leftLayout->addWidget(peopleTree);
        
        // Quick action buttons
        QHBoxLayout* leftButtonLayout = new QHBoxLayout();
        QPushButton* addPersonBtn = new QPushButton("Add Person", this);
        QPushButton* addAccountBtn = new QPushButton("Add Account", this);
        
        connect(addPersonBtn, &QPushButton::clicked, this, &MainWindow::onCreatePerson);
        connect(addAccountBtn, &QPushButton::clicked, this, &MainWindow::onCreateAccount);
        
        leftButtonLayout->addWidget(addPersonBtn);
        leftButtonLayout->addWidget(addAccountBtn);
        leftLayout->addLayout(leftButtonLayout);
        
        splitter->addWidget(leftWidget);
        
        // Right side: Transactions
        QWidget* rightWidget = new QWidget(this);
        QVBoxLayout* rightLayout = new QVBoxLayout(rightWidget);
        
        QLabel* transactionsLabel = new QLabel("Recent Transactions", this);
        font = transactionsLabel->font();
        font.setBold(true);
        transactionsLabel->setFont(font);
        rightLayout->addWidget(transactionsLabel);
        
        transactionsTable = new QTableWidget(this);
        transactionsTable->setColumnCount(5);
        transactionsTable->setHorizontalHeaderLabels({"Date", "Description", "Account", "Category", "Amount"});
        transactionsTable->horizontalHeader()->setStretchLastSection(true);
        transactionsTable->setSelectionBehavior(QAbstractItemView::SelectRows);
        transactionsTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
        transactionsTable->setAlternatingRowColors(true);
        rightLayout->addWidget(transactionsTable);
        
        // Transaction buttons
        QHBoxLayout* rightButtonLayout = new QHBoxLayout();
        QPushButton* addTransactionBtn = new QPushButton("Add Transaction", this);
        QPushButton* syncBankBtn = new QPushButton("Sync Bank", this);
        
        connect(addTransactionBtn, &QPushButton::clicked, this, &MainWindow::onCreateTransaction);
        connect(syncBankBtn, &QPushButton::clicked, this, &MainWindow::onSyncBank);
        
        rightButtonLayout->addWidget(addTransactionBtn);
        rightButtonLayout->addWidget(syncBankBtn);
        rightButtonLayout->addStretch();
        rightLayout->addLayout(rightButtonLayout);
        
        splitter->addWidget(rightWidget);
        splitter->setStretchFactor(0, 1);
        splitter->setStretchFactor(1, 2);
        
        mainLayout->addWidget(splitter);
        
        // Status label at bottom
        statusLabel = new QLabel("", this);
        statusLabel->setStyleSheet("QLabel { color: gray; font-style: italic; }");
        mainLayout->addWidget(statusLabel);
        
        setCentralWidget(centralWidget);
    }

    void setupConnections() {
        connect(service_, &FinanceService::dataChanged, this, &MainWindow::refreshData);
        connect(service_, &FinanceService::syncCompleted, this, &MainWindow::onSyncCompleted);
        connect(peopleTree, &QTreeWidget::itemSelectionChanged, this, &MainWindow::onTreeSelectionChanged);
    }

    void refreshData() {
        updatePeopleTree();
        updateTransactionsTable();
        updateNetWorth();
        statusLabel->setText("Last updated: " + QDateTime::currentDateTime().toString("hh:mm:ss"));
    }

    void updatePeopleTree() {
        peopleTree->clear();
        
        auto people = service_->getAllPeople();
        
        for (const Person* person : people) {
            QTreeWidgetItem* personItem = new QTreeWidgetItem(peopleTree);
            personItem->setText(0, QString::fromStdString(person->getName()));
            
            Money netWorth = service_->getTotalNetWorth(person->getId());
            personItem->setText(1, MoneyUtils::format(netWorth));
            
            if (netWorth >= 0) {
                personItem->setForeground(1, QBrush(QColor("#2E7D32")));
            } else {
                personItem->setForeground(1, QBrush(QColor("#C62828")));
            }
            
            auto accounts = service_->getAccountsForPerson(person->getId());
            for (const Account* account : accounts) {
                QTreeWidgetItem* accountItem = new QTreeWidgetItem(personItem);
                accountItem->setText(0, QString::fromStdString(account->getName()) + 
                                    " (" + account->getTypeString() + ")");
                accountItem->setText(1, MoneyUtils::format(account->getBalance()));
                
                if (account->getBalance() >= 0) {
                    accountItem->setForeground(1, QBrush(QColor("#2E7D32")));
                } else {
                    accountItem->setForeground(1, QBrush(QColor("#C62828")));
                }
                
                accountItem->setData(0, Qt::UserRole, QVariant::fromValue(account->getId()));
                Q_DECLARE_METATYPE(AccountId);
                qRegisterMetaType<AccountId>("AccountId");
            }
            
            personItem->setExpanded(true);
        }
    }

    void updateTransactionsTable() {
        transactionsTable->setRowCount(0);
        
        // Get all transactions from all accounts
        auto people = service_->getAllPeople();
        std::vector<const Transaction*> allTransactions;
        
        for (const Person* person : people) {
            auto accounts = service_->getAccountsForPerson(person->getId());
            for (const Account* account : accounts) {
                auto transactions = service_->getTransactionsForAccount(account->getId());
                allTransactions.insert(allTransactions.end(), transactions.begin(), transactions.end());
            }
        }
        
        // Sort by timestamp
        std::sort(allTransactions.begin(), allTransactions.end(),
                 [](const Transaction* a, const Transaction* b) {
                     return a->getTimestamp() > b->getTimestamp();
                 });
        
        // Show up to 50 most recent transactions
        int count = std::min(50, static_cast<int>(allTransactions.size()));
        transactionsTable->setRowCount(count);
        
        for (int i = 0; i < count; ++i) {
            const Transaction* txn = allTransactions[i];
            
            // Date
            auto time_t = std::chrono::system_clock::to_time_t(txn->getTimestamp());
            QDateTime dt = QDateTime::fromSecsSinceEpoch(time_t);
            transactionsTable->setItem(i, 0, new QTableWidgetItem(dt.toString("yyyy-MM-dd hh:mm")));
            
            // Description
            transactionsTable->setItem(i, 1, new QTableWidgetItem(QString::fromStdString(txn->getDescription())));
            
            // Account
            const Account* account = service_->getAccount(txn->getFromAccountId());
            if (account) {
                transactionsTable->setItem(i, 2, new QTableWidgetItem(QString::fromStdString(account->getName())));
            }
            
            // Category
            transactionsTable->setItem(i, 3, new QTableWidgetItem(QString::fromStdString(txn->getCategory())));
            
            // Amount
            QTableWidgetItem* amountItem = new QTableWidgetItem(MoneyUtils::format(txn->getAmount()));
            if (txn->getAmount() >= 0) {
                amountItem->setForeground(QBrush(QColor("#2E7D32")));
            } else {
                amountItem->setForeground(QBrush(QColor("#C62828")));
            }
            transactionsTable->setItem(i, 4, amountItem);
        }
        
        transactionsTable->resizeColumnsToContents();
    }

    void updateNetWorth() {
        auto people = service_->getAllPeople();
        Money totalNetWorth = 0;
        
        for (const Person* person : people) {
            totalNetWorth += service_->getTotalNetWorth(person->getId());
        }
        
        netWorthLabel->setText("Total Net Worth: " + MoneyUtils::format(totalNetWorth));
        
        if (totalNetWorth >= 0) {
            netWorthLabel->setStyleSheet("QLabel { color: #2E7D32; }");
        } else {
            netWorthLabel->setStyleSheet("QLabel { color: #C62828; }");
        }
    }

private slots:
    void onCreatePerson() {
        CreatePersonDialog dialog(this);
        if (dialog.exec() == QDialog::Accepted) {
            QString name = dialog.getName();
            QString email = dialog.getEmail();
            
            if (name.isEmpty()) {
                QMessageBox::warning(this, "Error", "Name cannot be empty!");
                return;
            }
            
            try {
                service_->createPerson(name, email);
                statusBar()->showMessage("Person created successfully", 3000);
            } catch (const std::exception& e) {
                QMessageBox::critical(this, "Error", QString("Failed to create person: ") + e.what());
            }
        }
    }

    void onCreateAccount() {
        auto people = service_->getAllPeople();
        
        if (people.empty()) {
            QMessageBox::information(this, "No People", "Please create a person first!");
            return;
        }
        
        CreateAccountDialog dialog(people, this);
        if (dialog.exec() == QDialog::Accepted) {
            QString name = dialog.getName();
            
            if (name.isEmpty()) {
                QMessageBox::warning(this, "Error", "Account name cannot be empty!");
                return;
            }
            
            try {
                Money balance = MoneyUtils::fromDollars(dialog.getBalance());
                service_->createAccount(dialog.getPersonId(), name, dialog.getType(), balance);
                statusBar()->showMessage("Account created successfully", 3000);
            } catch (const std::exception& e) {
                QMessageBox::critical(this, "Error", QString("Failed to create account: ") + e.what());
            }
        }
    }

    void onCreateTransaction() {
        auto people = service_->getAllPeople();
        std::vector<const Account*> allAccounts;
        
        for (const Person* person : people) {
            auto accounts = service_->getAccountsForPerson(person->getId());
            allAccounts.insert(allAccounts.end(), accounts.begin(), accounts.end());
        }
        
        if (allAccounts.empty()) {
            QMessageBox::information(this, "No Accounts", "Please create an account first!");
            return;
        }
        
        CreateTransactionDialog dialog(allAccounts, *service_, this);
        if (dialog.exec() == QDialog::Accepted) {
            QString description = dialog.getDescription();
            
            if (description.isEmpty()) {
                QMessageBox::warning(this, "Error", "Description cannot be empty!");
                return;
            }
            
            try {
                Money amount = MoneyUtils::fromDollars(dialog.getAmount());
                TransactionType type = dialog.getType();
                
                // For debits, make amount negative
                if (type == TransactionType::Debit) {
                    amount = -amount;
                }
                
                service_->createTransaction(dialog.getAccountId(), amount, type, description);
                statusBar()->showMessage("Transaction created successfully", 3000);
            } catch (const std::exception& e) {
                QMessageBox::critical(this, "Error", QString("Failed to create transaction: ") + e.what());
            }
        }
    }

    void onSyncBank() {
        auto people = service_->getAllPeople();
        std::vector<const Account*> allAccounts;
        
        for (const Person* person : people) {
            auto accounts = service_->getAccountsForPerson(person->getId());
            allAccounts.insert(allAccounts.end(), accounts.begin(), accounts.end());
        }
        
        if (allAccounts.empty()) {
            QMessageBox::information(this, "No Accounts", "Please create an account first!");
            return;
        }
        
        SyncBankDialog dialog(allAccounts, *service_, this);
        if (dialog.exec() == QDialog::Accepted) {
            QString credentials = dialog.getCredentials();
            
            if (credentials.isEmpty()) {
                QMessageBox::warning(this, "Error", "Credentials cannot be empty!");
                return;
            }
            
            statusBar()->showMessage("Syncing bank data...");
            service_->syncTransactionsFromBank(dialog.getAccountId(), credentials);
        }
    }

    void onTreeSelectionChanged() {
        QList<QTreeWidgetItem*> selected = peopleTree->selectedItems();
        if (selected.isEmpty()) return;
        
        QTreeWidgetItem* item = selected.first();
        QVariant data = item->data(0, Qt::UserRole);
        
        if (data.isValid()) {
            // An account was selected - could show its transactions
            AccountId accountId = data.value<AccountId>();
            // Future enhancement: filter transactions table by account
        }
    }

    void onSyncCompleted(int count) {
        statusBar()->showMessage(QString("Synced %1 transactions successfully!").arg(count), 5000);
        QMessageBox::information(this, "Sync Complete", 
                                QString("Successfully synced %1 transactions from bank.").arg(count));
    }
};

//entry point
int main(int argc, char* argv[]) {
    QApplication app(argc, argv);
    
    // Set application style
    app.setStyle("Fusion");
    
    // Initialize database
    QString dbPath = "finance_tracker.db";
    if (argc > 1) {
        dbPath = argv[1];
    }
    
    FinanceDatabaseManager dbManager;
    if (!dbManager.initialize(dbPath)) {
        QMessageBox::critical(nullptr, "Database Error", 
                            "Failed to initialize database at: " + dbPath);
        return 1;
    }
    
    // Create service
    FinanceService service(dbManager);
    
    // Create and show main window
    MainWindow window(&service);
    window.show();
    
    return app.exec();
}

