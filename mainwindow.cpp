#include "mainwindow.h"
#include "ui_MainWindow.h"
#include "exporter.h"
#include "exportformatdialog.h"
#include <QFileDialog>
#include <QMessageBox>
#include <QInputDialog>
#include <QtCrypto/QtCrypto>
#include "kuz_calc.h"
#include <functional>

MainWindow::MainWindow(QWidget* parent)
    : QMainWindow(parent), ui(new Ui::MainWindow) {
    ui->setupUi(this);

    // Имена шифров
    cipherNames = {"Caesar", "Atbash", "Beaufort", "Kuznechik", "RSA", "AES-256", "Blowfish", "3DES", "CAST5"};

    // Инициализация функций шифрования с помощью std::bind
    cipherFuncs.push_back(std::function<QString(MainWindow*, const QString&, const QString&, const QString&)>(
        [this](MainWindow* obj, const QString& text, const QString& key, const QString& alphabet) {
            return this->caesarEncrypt(text, key, alphabet);
        }));
    cipherFuncs.push_back(std::function<QString(MainWindow*, const QString&, const QString&, const QString&)>(
        [this](MainWindow* obj, const QString& text, const QString& key, const QString& alphabet) {
            return this->atbashEncrypt(text, key, alphabet);
        }));
    cipherFuncs.push_back(std::function<QString(MainWindow*, const QString&, const QString&, const QString&)>(
        [this](MainWindow* obj, const QString& text, const QString& key, const QString& alphabet) {
            return this->beaufortEncrypt(text, key, alphabet);
        }));
    cipherFuncs.push_back(std::function<QString(MainWindow*, const QString&, const QString&, const QString&)>(
        [this](MainWindow* obj, const QString& text, const QString& key, const QString& alphabet) {
            return this->kuznechikEncrypt(text, key, alphabet);
        }));
    cipherFuncs.push_back(std::function<QString(MainWindow*, const QString&, const QString&, const QString&)>(
        [this](MainWindow* obj, const QString& text, const QString& key, const QString& alphabet) {
            return this->rsaEncrypt(text, key, alphabet);
        }));
    cipherFuncs.push_back(std::function<QString(MainWindow*, const QString&, const QString&, const QString&)>(
        [this](MainWindow* obj, const QString& text, const QString& key, const QString& alphabet) {
            return this->aes256Encrypt(text, key, alphabet);
        }));
    cipherFuncs.push_back(std::function<QString(MainWindow*, const QString&, const QString&, const QString&)>(
        [this](MainWindow* obj, const QString& text, const QString& key, const QString& alphabet) {
            return this->blowfishEncrypt(text, key, alphabet);
        }));
    cipherFuncs.push_back(std::function<QString(MainWindow*, const QString&, const QString&, const QString&)>(
        [this](MainWindow* obj, const QString& text, const QString& key, const QString& alphabet) {
            return this->tripleDesEncrypt(text, key, alphabet);
        }));
    cipherFuncs.push_back(std::function<QString(MainWindow*, const QString&, const QString&, const QString&)>(
        [this](MainWindow* obj, const QString& text, const QString& key, const QString& alphabet) {
            return this->cast5Encrypt(text, key, alphabet);
        }));

    // Соединения
    connect(ui->alphabetSelector, &QComboBox::currentIndexChanged, this, &MainWindow::onAlphabetChanged);
    connect(ui->cipherSelector, &QComboBox::currentIndexChanged, this, &MainWindow::onCipherChanged);
    connect(ui->encryptButton, &QPushButton::clicked, this, &MainWindow::encryptText);
    connect(ui->decryptButton, &QPushButton::clicked, this, &MainWindow::decryptText);
    connect(ui->exportButton, &QPushButton::clicked, this, &MainWindow::exportResult);
    connect(ui->generateKeysButton, &QPushButton::clicked, this, &MainWindow::generateRsaKeys);

    // Инициализация QCA
    static QCA::Initializer init;

    onAlphabetChanged(0);
    onCipherChanged(0);
}

MainWindow::~MainWindow() {
    delete ui;
}

void MainWindow::onCipherChanged(int index) {
    ui->cipherInputStack->setCurrentIndex(index);
    ui->decryptButton->setEnabled(index == 4 || index == 5 || index == 6 || index == 7 || index == 8 || index == 3);
}

void MainWindow::onAlphabetChanged(int index) {
    if (index == 0) {
        currentAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    } else if (index == 1) {
        currentAlphabet = QString::fromUtf8("АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ");
    } else {
        bool ok;
        QString txt = QInputDialog::getText(
            this,
            "Custom Alphabet",
            "Введите буквы алфавита:",
            QLineEdit::Normal,
            "",
            &ok
            );
        currentAlphabet = (ok && !txt.isEmpty()) ? txt : "";
    }
    updateAlphabetDisplay();
}

void MainWindow::updateAlphabetDisplay() {
    ui->alphabetDisplay->setText(currentAlphabet);
}

void MainWindow::generateRsaKeys() {
    QCA::KeyGenerator keyGen;
    QCA::PrivateKey privateKey = keyGen.createRSA(2048);
    if (privateKey.isNull()) {
        QMessageBox::warning(this, "Ошибка", "Не удалось сгенерировать ключи.");
        return;
    }
    QCA::PublicKey publicKey = privateKey.toPublicKey();
    rsaPublicKey = publicKey.toPEM();
    rsaPrivateKey = privateKey.toPEM();
    ui->publicKeyInput->setPlainText(rsaPublicKey);
    ui->privateKeyInput->setPlainText(rsaPrivateKey);
}

QString MainWindow::crypt(QString data) {
    unsigned char str_arr[STR_SIZE];
    unsigned char key_arr[KEY_SIZE];
    unsigned char vect_arr[VECT_SIZE];

    std::string key_str = ui->kuznechikKeyInput->text().toStdString();
    std::string vect_str = ui->kuznechikVectorInput->text().toStdString() + "0000000000000000";
    std::string data_str = data.toStdString();

    int size = data_str.length();
    uint8_t out_buf[size];

    QString result;

    if (vect_str.length() != VECT_SIZE + 16) {
        return "Вектор должен быть 8 байт";
    } else if (key_str.length() != 64) {
        return "Ключ должен быть 32 байта";
    } else if (size % 16) {
        return "Строка должна быть кратна 16";
    } else {
        key_str = reverse_hex(key_str);
        vect_str = reverse_hex(vect_str);

        convert_hex(str_arr, data_str.c_str(), size);
        convert_hex(key_arr, key_str.c_str(), KEY_SIZE);
        convert_hex(vect_arr, vect_str.c_str(), VECT_SIZE);

        Kuznechik kuz;
        kuz.CTR_Crypt(vect_arr, str_arr, out_buf, key_arr, size);

        result = QString::fromStdString(convert_to_string(out_buf, size / 2));
    }
    return result;
}

void MainWindow::encryptText() {
    int idx = ui->cipherSelector->currentIndex();
    QString text = ui->inputText->toPlainText();
    QString key;
    QString vector;
    QString result;

    if (text.isEmpty()) {
        QMessageBox::warning(this, "Ошибка", "Введите текст для шифрования.");
        return;
    }

    // Получить ключ и вектор в зависимости от шифра
    if (idx == 0) { // Caesar
        key = ui->caesarKeyInput->text();
    } else if (idx == 2) { // Beaufort
        key = ui->beaufortKeyInput->text();
    } else if (idx == 3) { // Kuznechik
        key = ui->kuznechikKeyInput->text();
        vector = ui->kuznechikVectorInput->text();
    } else if (idx == 4) { // RSA
        if (rsaPublicKey.isEmpty() || rsaPrivateKey.isEmpty()) {
            generateRsaKeys();
        }
        key = rsaPublicKey;
    } else if (idx == 5) { // AES-256
        key = ui->aes256KeyInput->text();
    } else if (idx == 6) { // Blowfish
        key = ui->blowfishKeyInput->text();
    } else if (idx == 7) { // 3DES
        key = ui->tripleDesKeyInput->text();
    } else if (idx == 8) { // CAST5
        key = ui->cast5KeyInput->text();
    } // Atbash (idx == 1) не требует ключа

    result = cipherFuncs[idx](this, text, key, currentAlphabet);
    if (result.startsWith("Ошибка:")) {
        QMessageBox::warning(this, "Ошибка", result);
        return;
    }
    ui->outputText->setPlainText(result);
}

void MainWindow::decryptText() {
    int idx = ui->cipherSelector->currentIndex();
    QString base64Text = ui->inputText->toPlainText();
    QString key;
    QString vector;
    QString result;

    if (base64Text.isEmpty()) {
        QMessageBox::warning(this, "Ошибка", "Введите текст для расшифровки.");
        return;
    }

    if (idx == 3) { // Kuznechik
        key = ui->kuznechikKeyInput->text();
        vector = ui->kuznechikVectorInput->text();
        result = crypt(base64Text); // Кузнечик симметричен, повторное шифрование = расшифровка
    } else if (idx == 4) { // RSA
        key = ui->privateKeyInput->toPlainText();
        if (key.isEmpty()) {
            QMessageBox::warning(this, "Ошибка", "Введите приватный ключ для расшифровки.");
            return;
        }
        result = rsaDecrypt(base64Text, key);
    } else if (idx == 5) { // AES-256
        key = ui->aes256KeyInput->text();
        result = aes256Decrypt(base64Text, key);
    } else if (idx == 6) { // Blowfish
        key = ui->blowfishKeyInput->text();
        result = blowfishDecrypt(base64Text, key);
    } else if (idx == 7) { // 3DES
        key = ui->tripleDesKeyInput->text();
        result = tripleDesDecrypt(base64Text, key);
    } else if (idx == 8) { // CAST5
        key = ui->cast5KeyInput->text();
        result = cast5Decrypt(base64Text, key);
    } else {
        QMessageBox::warning(this, "Ошибка", "Расшифровка доступна только для Kuznechik, RSA, AES-256, Blowfish, 3DES и CAST5.");
        return;
    }

    if (result.startsWith("Ошибка:")) {
        QMessageBox::warning(this, "Ошибка", result);
        return;
    }
    ui->outputText->setPlainText(result);
}

void MainWindow::exportResult() {
    // Показываем диалоговое окно для выбора формата
    ExportFormatDialog dialog(this);
    if (dialog.exec() != QDialog::Accepted) {
        return; // Пользователь отменил выбор
    }

    QString format = dialog.getSelectedFormat();
    if (format.isEmpty()) {
        QMessageBox::warning(this, "Ошибка", "Формат не выбран.");
        return;
    }

    // Определяем фильтр и расширение файла на основе выбранного формата
    QString filter;
    QString defaultExtension;
    if (format == "txt") {
        filter = "Text Files (*.txt)";
        defaultExtension = ".txt";
    } else if (format == "html") {
        filter = "HTML Files (*.html)";
        defaultExtension = ".html";
    } else if (format == "json") {
        filter = "JSON Files (*.json)";
        defaultExtension = ".json";
    } else {
        QMessageBox::warning(this, "Ошибка", "Неподдерживаемый формат.");
        return;
    }

    // Открываем диалог сохранения файла с нужным фильтром
    QString filename = QFileDialog::getSaveFileName(
        this,
        "Сохранить результат",
        QString(),
        filter
        );
    if (filename.isEmpty()) {
        return;
    }

    // Добавляем расширение, если пользователь его не указал
    if (!filename.endsWith(defaultExtension)) {
        filename += defaultExtension;
    }

    bool ok;
    int idx = ui->cipherSelector->currentIndex();
    QString cipherName = cipherNames[idx]; // Получаем название текущего шифра
    if (idx == 4) { // RSA
        ok = Exporter::exportToFile(
            filename,
            ui->inputText->toPlainText(),
            ui->outputText->toPlainText(),
            cipherName,
            rsaPublicKey,
            rsaPrivateKey,
            format
            );
    } else {
        ok = Exporter::exportToFile(
            filename,
            ui->inputText->toPlainText(),
            ui->outputText->toPlainText(),
            cipherName,
            QString(), // Пустой publicKey
            QString(), // Пустой privateKey
            format
            );
    }
    if (!ok) {
        QMessageBox::warning(this, "Ошибка", "Не удалось сохранить файл.");
    } else {
        QMessageBox::information(this, "Готово", "Файл сохранён.");
    }
}

// Реализации функций шифрования
QString MainWindow::caesarEncrypt(const QString& text, const QString& key, const QString& alphabet) {
    if (text.isEmpty() || alphabet.isEmpty()) return "Ошибка: Пустой текст или алфавит";
    bool ok;
    int shift = key.toInt(&ok);
    if (!ok || shift < 0) return "Ошибка: Неверный ключ (ожидается целое число)";

    QString result;
    for (const QChar& c : text) {
        int pos = alphabet.indexOf(c.toUpper());
        if (pos != -1) {
            int newPos = (pos + shift) % alphabet.length();
            result += alphabet[newPos];
        } else {
            result += c;
        }
    }
    return result;
}

QString MainWindow::atbashEncrypt(const QString& text, const QString& key, const QString& alphabet) {
    Q_UNUSED(key);
    if (text.isEmpty() || alphabet.isEmpty()) return "Ошибка: Пустой текст или алфавит";

    QString result;
    for (const QChar& c : text) {
        int pos = alphabet.indexOf(c.toUpper());
        if (pos != -1) {
            int newPos = alphabet.length() - 1 - pos;
            result += alphabet[newPos];
        } else {
            result += c;
        }
    }
    return result;
}

QString MainWindow::beaufortEncrypt(const QString& text, const QString& key, const QString& alphabet) {
    if (text.isEmpty() || key.isEmpty() || alphabet.isEmpty()) return "Ошибка: Пустой текст, ключ или алфавит";

    QString result;
    QString expandedKey = key;
    while (expandedKey.length() < text.length()) {
        expandedKey += key;
    }
    expandedKey = expandedKey.left(text.length());

    for (int i = 0; i < text.length(); ++i) {
        int textPos = alphabet.indexOf(text[i].toUpper());
        int keyPos = alphabet.indexOf(expandedKey[i].toUpper());
        if (textPos != -1 && keyPos != -1) {
            int newPos = (keyPos - textPos + alphabet.length()) % alphabet.length();
            result += alphabet[newPos];
        } else {
            result += text[i];
        }
    }
    return result;
}

QString MainWindow::kuznechikEncrypt(const QString& text, const QString& key, const QString& alphabet) {
    Q_UNUSED(key);
    Q_UNUSED(alphabet);
    return crypt(text);
}

QString MainWindow::rsaEncrypt(const QString& text, const QString& key, const QString& alphabet) {
    Q_UNUSED(alphabet);
    if (text.isEmpty()) return "Ошибка: Пустой текст";
    if (key.isEmpty()) return "Ошибка: Пустой ключ";

    QCA::PublicKey pubKey;
    pubKey.fromPEM(key);
    if (!pubKey.canEncrypt()) return "Ошибка: Неверный публичный ключ";

    QCA::SecureArray data = text.toUtf8();
    QCA::SecureArray encrypted = pubKey.encrypt(data, QCA::EME_PKCS1v15);
    if (encrypted.isEmpty()) return "Ошибка: Не удалось зашифровать";

    return QString(encrypted.toByteArray().toBase64());
}

QString MainWindow::aes256Encrypt(const QString& text, const QString& key, const QString& alphabet) {
    Q_UNUSED(alphabet);
    if (text.isEmpty()) return "Ошибка: Пустой текст";
    if (key.isEmpty()) return "Ошибка: Пустой ключ";

    QCA::SymmetricKey symKey(key.toUtf8());
    QCA::InitializationVector iv(16);
    QCA::Cipher cipher("aes256", QCA::Cipher::CBC, QCA::Cipher::DefaultPadding, QCA::Encode, symKey, iv);

    QCA::SecureArray data = text.toUtf8();
    QCA::SecureArray encrypted = cipher.process(data);
    if (!cipher.ok()) return "Ошибка: Не удалось зашифровать";

    return QString((iv + encrypted).toByteArray().toBase64());
}

QString MainWindow::blowfishEncrypt(const QString& text, const QString& key, const QString& alphabet) {
    Q_UNUSED(alphabet);
    if (text.isEmpty()) return "Ошибка: Пустой текст";
    if (key.isEmpty()) return "Ошибка: Пустой ключ";

    QCA::SymmetricKey symKey(key.toUtf8());
    QCA::InitializationVector iv(8);
    QCA::Cipher cipher("blowfish", QCA::Cipher::CBC, QCA::Cipher::DefaultPadding, QCA::Encode, symKey, iv);

    QCA::SecureArray data = text.toUtf8();
    QCA::SecureArray encrypted = cipher.process(data);
    if (!cipher.ok()) return "Ошибка: Не удалось зашифровать";

    return QString((iv + encrypted).toByteArray().toBase64());
}

QString MainWindow::tripleDesEncrypt(const QString& text, const QString& key, const QString& alphabet) {
    Q_UNUSED(alphabet);
    if (text.isEmpty()) return "Ошибка: Пустой текст";
    if (key.isEmpty()) return "Ошибка: Пустой ключ";

    QCA::SymmetricKey symKey(key.toUtf8());
    QCA::InitializationVector iv(8);
    QCA::Cipher cipher("tripledes", QCA::Cipher::CBC, QCA::Cipher::DefaultPadding, QCA::Encode, symKey, iv);

    QCA::SecureArray data = text.toUtf8();
    QCA::SecureArray encrypted = cipher.process(data);
    if (!cipher.ok()) return "Ошибка: Не удалось зашифровать";

    return QString((iv + encrypted).toByteArray().toBase64());
}

QString MainWindow::cast5Encrypt(const QString& text, const QString& key, const QString& alphabet) {
    Q_UNUSED(alphabet);
    if (text.isEmpty()) return "Ошибка: Пустой текст";
    if (key.isEmpty()) return "Ошибка: Пустой ключ";

    QCA::SymmetricKey symKey(key.toUtf8());
    QCA::InitializationVector iv(8);
    QCA::Cipher cipher("cast5", QCA::Cipher::CBC, QCA::Cipher::DefaultPadding, QCA::Encode, symKey, iv);

    QCA::SecureArray data = text.toUtf8();
    QCA::SecureArray encrypted = cipher.process(data);
    if (!cipher.ok()) return "Ошибка: Не удалось зашифровать";

    return QString((iv + encrypted).toByteArray().toBase64());
}

// Реализации функций расшифровки
QString MainWindow::rsaDecrypt(const QString& text, const QString& key) {
    if (text.isEmpty()) return "Ошибка: Пустой текст";
    if (key.isEmpty()) return "Ошибка: Пустой ключ";

    QCA::PrivateKey privKey;
    privKey.fromPEM(key);
    if (!privKey.canDecrypt()) return "Ошибка: Неверный приватный ключ";

    QByteArray encrypted = QByteArray::fromBase64(text.toUtf8());
    QCA::SecureArray data(encrypted);
    QCA::SecureArray out;
    bool success = privKey.decrypt(data, &out, QCA::EME_PKCS1v15);
    if (!success || out.isEmpty()) return "Ошибка: Не удалось расшифровать";

    return QString::fromUtf8(out.data());
}

QString MainWindow::aes256Decrypt(const QString& text, const QString& key) {
    if (text.isEmpty()) return "Ошибка: Пустой текст";
    if (key.isEmpty()) return "Ошибка: Пустой ключ";

    QByteArray encrypted = QByteArray::fromBase64(text.toUtf8());
    if (encrypted.size() < 16) return "Ошибка: Неверный формат данных";

    QCA::InitializationVector iv(encrypted.left(16));
    QCA::SecureArray data(encrypted.mid(16));
    QCA::SymmetricKey symKey(key.toUtf8());
    QCA::Cipher cipher("aes256", QCA::Cipher::CBC, QCA::Cipher::DefaultPadding, QCA::Decode, symKey, iv);

    QCA::SecureArray decrypted = cipher.process(data);
    if (!cipher.ok()) return "Ошибка: Не удалось расшифровать";

    return QString::fromUtf8(decrypted.data());
}

QString MainWindow::blowfishDecrypt(const QString& text, const QString& key) {
    if (text.isEmpty()) return "Ошибка: Пустой текст";
    if (key.isEmpty()) return "Ошибка: Пустой ключ";

    QByteArray encrypted = QByteArray::fromBase64(text.toUtf8());
    if (encrypted.size() < 8) return "Ошибка: Неверный формат данных";

    QCA::InitializationVector iv(encrypted.left(8));
    QCA::SecureArray data(encrypted.mid(8));
    QCA::SymmetricKey symKey(key.toUtf8());
    QCA::Cipher cipher("blowfish", QCA::Cipher::CBC, QCA::Cipher::DefaultPadding, QCA::Decode, symKey, iv);

    QCA::SecureArray decrypted = cipher.process(data);
    if (!cipher.ok()) return "Ошибка: Не удалось расшифровать";

    return QString::fromUtf8(decrypted.data());
}

QString MainWindow::tripleDesDecrypt(const QString& text, const QString& key) {
    if (text.isEmpty()) return "Ошибка: Пустой текст";
    if (key.isEmpty()) return "Ошибка: Пустой ключ";

    QByteArray encrypted = QByteArray::fromBase64(text.toUtf8());
    if (encrypted.size() < 8) return "Ошибка: Неверный формат данных";

    QCA::InitializationVector iv(encrypted.left(8));
    QCA::SecureArray data(encrypted.mid(8));
    QCA::SymmetricKey symKey(key.toUtf8());
    QCA::Cipher cipher("tripledes", QCA::Cipher::CBC, QCA::Cipher::DefaultPadding, QCA::Decode, symKey, iv);

    QCA::SecureArray decrypted = cipher.process(data);
    if (!cipher.ok()) return "Ошибка: Не удалось расшифровать";

    return QString::fromUtf8(decrypted.data());
}

QString MainWindow::cast5Decrypt(const QString& text, const QString& key) {
    if (text.isEmpty()) return "Ошибка: Пустой текст";
    if (key.isEmpty()) return "Ошибка: Пустой ключ";

    QByteArray encrypted = QByteArray::fromBase64(text.toUtf8());
    if (encrypted.size() < 8) return "Ошибка: Неверный формат данных";

    QCA::InitializationVector iv(encrypted.left(8));
    QCA::SecureArray data(encrypted.mid(8));
    QCA::SymmetricKey symKey(key.toUtf8());
    QCA::Cipher cipher("cast5", QCA::Cipher::CBC, QCA::Cipher::DefaultPadding, QCA::Decode, symKey, iv);

    QCA::SecureArray decrypted = cipher.process(data);
    if (!cipher.ok()) return "Ошибка: Не удалось расшифровать";

    return QString::fromUtf8(decrypted.data());
}
