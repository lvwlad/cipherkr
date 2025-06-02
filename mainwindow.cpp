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
#include <QDebug>

MainWindow::MainWindow(QWidget* parent)
    : QMainWindow(parent), ui(new Ui::MainWindow) {
    ui->setupUi(this);

    // Имена шифров
    cipherNames = {"Caesar", "Atbash", "Beaufort", "Kuznechik", "RSA", "AES-256", "Blowfish", "3DES", "CAST5"};

    // Инициализация функций шифрования с помощью лямбда-выражений
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
    qDebug() << "QCA Providers:";
    foreach (QCA::Provider* provider, QCA::providers()) {
        qDebug() << "  - Provider:" << provider->name() << "(Features:" << provider->features().join(", ") << ")";
    }
    if (!QCA::isSupported("rsa")) {
        qDebug() << "RSA support is not available in QCA";
        QMessageBox::critical(this, "Ошибка", "RSA support is not available. Check QCA installation.");
    } else {
        qDebug() << "RSA support is available";
    }

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
        rsaPublicKey.clear();
        rsaPrivateKey.clear();
        return;
    }
    QCA::PublicKey publicKey = privateKey.toPublicKey();
    rsaPublicKey = publicKey.toPEM();
    rsaPrivateKey = privateKey.toPEM();
    ui->publicKeyInput->setPlainText(rsaPublicKey);
    ui->privateKeyInput->setPlainText(rsaPrivateKey);
    qDebug() << "Generated public key length:" << rsaPublicKey.length();
    qDebug() << "Generated private key length:" << rsaPrivateKey.length();
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
        if (rsaPublicKey.isEmpty()) {
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
        if (rsaPrivateKey.isEmpty()) {
            QMessageBox::warning(this, "Ошибка", "Приватный ключ отсутствует. Пожалуйста, сгенерируйте ключи.");
            generateRsaKeys();
            return;
        }
        key = rsaPrivateKey; // Use the stored rsaPrivateKey
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
    ExportFormatDialog dialog(this);
    if (dialog.exec() != QDialog::Accepted) {
        return;
    }

    QString format = dialog.getSelectedFormat();
    if (format.isEmpty()) {
        QMessageBox::warning(this, "Ошибка", "Формат не выбран.");
        return;
    }

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

    QString filename = QFileDialog::getSaveFileName(
        this,
        "Сохранить результат",
        QString(),
        filter
        );
    if (filename.isEmpty()) {
        return;
    }

    if (!filename.endsWith(defaultExtension)) {
        filename += defaultExtension;
    }

    bool ok;
    int idx = ui->cipherSelector->currentIndex();
    QString cipherName = cipherNames[idx];
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
            QString(),
            QString(),
            format
            );
    }
    if (!ok) {
        QMessageBox::warning(this, "Ошибка", "Не удалось сохранить файл.");
    } else {
        QMessageBox::information(this, "Готово", "Файл сохранён.");
    }
}

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

    QCA::PublicKey pubKey = QCA::PublicKey::fromPEM(key.toUtf8());
    if (pubKey.isNull()) {
        qDebug() << "Public key loading failed. Key data:" << key.left(50) << "...";
        return "Ошибка: Неверный публичный ключ";
    }

    QCA::SecureArray encrypted = pubKey.encrypt(text.toUtf8(), QCA::EME_PKCS1_OAEP);
    if (encrypted.isEmpty()) {
        qDebug() << "Encryption failed.";
        return "Ошибка: Не удалось зашифровать";
    }

    return QString(encrypted.toByteArray().toBase64());
}

QString MainWindow::rsaDecrypt(const QString& text, const QString& key) {
    if (text.isEmpty()) return "Ошибка: Пустой текст";
    if (key.isEmpty()) return "Ошибка: Пустой ключ";

    QCA::PrivateKey privKey = QCA::PrivateKey::fromPEM(key.toUtf8());
    if (privKey.isNull()) {
        qDebug() << "Private key loading failed. Key data:" << key.left(50) << "...";
        return "Ошибка: Неверный приватный ключ";
    }

    QByteArray encrypted = QByteArray::fromBase64(text.toUtf8());
    if (encrypted.isEmpty()) {
        qDebug() << "Invalid base64 data.";
        return "Ошибка: Неверный формат зашифрованного текста";
    }

    QCA::SecureArray decrypted;
    bool success = privKey.decrypt(encrypted, &decrypted, QCA::EME_PKCS1_OAEP);
    if (!success || decrypted.isEmpty()) {
        qDebug() << "Decryption failed. Success:" << success << ", Decrypted size:" << decrypted.size();
        return "Ошибка: Не удалось расшифровать";
    }

    return QString::fromUtf8(decrypted.data(), decrypted.size());
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
    if (text.isEmpty()) {
        qDebug() << "3DES Encrypt: Empty input text";
        return "Ошибка: Пустой текст";
    }
    if (key.isEmpty()) {
        qDebug() << "3DES Encrypt: Empty key";
        return "Ошибка: Пустой ключ";
    }

    QByteArray keyBytes = key.toUtf8();
    qDebug() << "3DES Encrypt: Original key length (chars):" << key.length()
             << "Key length (bytes after toUtf8):" << keyBytes.length();

    if (keyBytes.length() < 24) {
        keyBytes = keyBytes.leftJustified(24, '\0');
        qDebug() << "3DES Encrypt: Key padded to 24 bytes";
    } else if (keyBytes.length() > 24) {
        keyBytes = keyBytes.left(24);
        qDebug() << "3DES Encrypt: Key truncated to 24 bytes";
    }

    QCA::SymmetricKey symKey(keyBytes);
    qDebug() << "3DES Encrypt: Symmetric key created, length:" << symKey.size();

    QCA::Cipher cipher("tripledes", QCA::Cipher::ECB, QCA::Cipher::NoPadding, QCA::Encode, symKey);
    qDebug() << "3DES Encrypt: Cipher initialized with ECB mode and NoPadding";

    QCA::SecureArray data = text.toUtf8();
    if (data.isEmpty()) {
        qDebug() << "3DES Encrypt: Input data is empty after toUtf8";
        return "Ошибка: Некорректные входные данные";
    }
    qDebug() << "3DES Encrypt: Input data length:" << data.size() << "Data (hex):" << data.toByteArray().toHex();

    // Ручное дополнение данных до кратности 8 байт
    QCA::SecureArray paddedData = padData(data, 8);

    QCA::SecureArray encrypted = cipher.process(paddedData);
    if (!cipher.ok() || encrypted.isEmpty()) {
        qDebug() << "3DES Encrypt: Encryption failed. Cipher ok:" << cipher.ok()
        << "Encrypted data length:" << encrypted.size();
        return "Ошибка: Не удалось зашифровать";
    }

    qDebug() << "3DES Encrypt: Encryption successful. Encrypted data length:" << encrypted.size()
             << "Data (hex):" << encrypted.toByteArray().toHex();
    return QString(encrypted.toByteArray().toBase64());
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
    if (text.isEmpty()) {
        qDebug() << "3DES Decrypt: Empty input text";
        return "Ошибка: Пустой текст";
    }
    if (key.isEmpty()) {
        qDebug() << "3DES Decrypt: Empty key";
        return "Ошибка: Пустой ключ";
    }

    QByteArray encrypted = QByteArray::fromBase64(text.toUtf8());
    if (encrypted.isEmpty()) {
        qDebug() << "3DES Decrypt: Invalid Base64 data";
        return "Ошибка: Неверный формат данных";
    }
    qDebug() << "3DES Decrypt: Encrypted data length:" << encrypted.size()
             << "Data (hex):" << encrypted.toHex();

    QByteArray keyBytes = key.toUtf8();
    qDebug() << "3DES Decrypt: Original key length (chars):" << key.length()
             << "Key length (bytes after toUtf8):" << keyBytes.length();

    if (keyBytes.length() < 24) {
        keyBytes = keyBytes.leftJustified(24, '\0');
        qDebug() << "3DES Decrypt: Key padded to 24 bytes";
    } else if (keyBytes.length() > 24) {
        keyBytes = keyBytes.left(24);
        qDebug() << "3DES Decrypt: Key truncated to 24 bytes";
    }

    QCA::SymmetricKey symKey(keyBytes);
    qDebug() << "3DES Decrypt: Symmetric key created, length:" << symKey.size();

    QCA::Cipher cipher("tripledes", QCA::Cipher::ECB, QCA::Cipher::NoPadding, QCA::Decode, symKey);
    qDebug() << "3DES Decrypt: Cipher initialized with ECB mode and NoPadding";

    QCA::SecureArray data(encrypted);
    QCA::SecureArray decrypted = cipher.process(data);
    if (!cipher.ok() || decrypted.isEmpty()) {
        qDebug() << "3DES Decrypt: Decryption failed. Cipher ok:" << cipher.ok()
        << "Decrypted data length:" << decrypted.size();
        return "Ошибка: Не удалось расшифровать";
    }

    // Удаляем дополнение
    QCA::SecureArray unpaddedData = unpadData(decrypted);
    qDebug() << "3DES Decrypt: Decryption successful. Decrypted data length:" << unpaddedData.size()
             << "Data (hex):" << unpaddedData.toByteArray().toHex();

    QString result = QString::fromUtf8(unpaddedData.data(), unpaddedData.size());
    qDebug() << "3DES Decrypt: Decoded result:" << result;
    return result;
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

// Вспомогательные функции для ручного дополнения и удаления дополнения
QCA::SecureArray MainWindow::padData(const QCA::SecureArray& data, int blockSize) {
    int paddingSize = blockSize - (data.size() % blockSize);
    QCA::SecureArray paddedData(data);
    paddedData.resize(data.size() + paddingSize);
    for (int i = 0; i < paddingSize; ++i) {
        paddedData[data.size() + i] = static_cast<char>(paddingSize);
    }
    qDebug() << "Padded data length:" << paddedData.size() << "Data (hex):" << paddedData.toByteArray().toHex();
    return paddedData;
}

QCA::SecureArray MainWindow::unpadData(const QCA::SecureArray& data) {
    if (data.isEmpty()) return data;
    int paddingSize = static_cast<unsigned char>(data[data.size() - 1]);
    if (paddingSize > data.size() || paddingSize == 0) {
        qDebug() << "Invalid padding size:" << paddingSize;
        return data; // Некорректное дополнение, возвращаем как есть
    }
    // Проверяем, что все байты дополнения корректны
    for (int i = 0; i < paddingSize; ++i) {
        if (static_cast<unsigned char>(data[data.size() - 1 - i]) != paddingSize) {
            qDebug() << "Invalid padding bytes at position" << (data.size() - 1 - i);
            return data;
        }
    }
    QCA::SecureArray unpaddedData(data);
    unpaddedData.resize(data.size() - paddingSize);
    qDebug() << "Unpadded data length:" << unpaddedData.size() << "Data (hex):" << unpaddedData.toByteArray().toHex();
    return unpaddedData;
}
