#include "mainwindow.h"
#include "./ui_MainWindow.h"
#include "exporter.h"
#include "exportformatdialog.h"
#include <QFileDialog>
#include <QMessageBox>
#include <QInputDialog>
#include <QtCrypto>
#include <QRandomGenerator>
#include "kuz_calc.h"
#include <functional>
#include <QFormLayout>


MainWindow::MainWindow(QWidget* parent) : QMainWindow(parent), ui(new Ui::MainWindow) {
    ui->setupUi(this);
    
    // Принудительное обновление стилей
    this->style()->unpolish(this);
    this->style()->polish(this);

    // Инициализация списка имен шифров
    cipherNames = {
        "Caesar",
        "Atbash",
        "Beaufort",
        "Kuznechik",
        "RSA",
        "AES-256",
        "Blowfish",
        "3DES",
        "CAST5"
    };

    // Заполнение селектора шифров
    for (const QString& name : cipherNames) {
        ui->cipherSelector->addItem(name);
    }

    // Заполнение селектора алфавитов
    ui->alphabetSelector->addItem("English (A-Z)");
    ui->alphabetSelector->addItem("Russian (А-Я)");
    ui->alphabetSelector->addItem("Custom");


    // Валидаторы для Kuznechik
    QRegularExpression hexRegex("^[0-9a-fA-F]*$");
    QValidator* hexValidator = new QRegularExpressionValidator(hexRegex, this);
    ui->kuznechikKeyInput->setValidator(hexValidator);
    ui->kuznechikVectorInput->setValidator(hexValidator);

    // Контекстное меню для RSA-ключей
    connect(ui->publicKeyInput, &QPlainTextEdit::textChanged, this, [&]() {
        ui->publicKeyInput->setToolTip("Нажмите правой кнопкой мыши для копирования");
    });
    connect(ui->privateKeyInput, &QPlainTextEdit::textChanged, this, [&]() {
        ui->privateKeyInput->setToolTip("Нажмите правой кнопкой мыши для копирования");
    });


    // Инициализация функций шифрования (мой подход)
    cipherFuncs = {
        &MainWindow::caesarEncrypt,
        &MainWindow::atbashEncrypt,
        &MainWindow::beaufortEncrypt,
        &MainWindow::kuznechikEncrypt,
        &MainWindow::rsaEncrypt,
        &MainWindow::aes256Encrypt,
        &MainWindow::blowfishEncrypt,
        &MainWindow::tripleDesEncrypt,
        &MainWindow::cast5Encrypt
    };

    // Соединения
    connect(ui->alphabetSelector, QOverload<int>::of(&QComboBox::currentIndexChanged), this, &MainWindow::onAlphabetChanged);
    connect(ui->cipherSelector, QOverload<int>::of(&QComboBox::currentIndexChanged), this, [this](int index) {
        onCipherChanged(index);
    });
    connect(ui->decryptButton, &QPushButton::clicked, this, &MainWindow::decryptText);
    connect(ui->encryptButton, &QPushButton::clicked, this, &MainWindow::encryptText);
    connect(ui->exportButton, &QPushButton::clicked, this, &MainWindow::exportResult);
    connect(ui->generateKeysButton, &QPushButton::clicked, this, &MainWindow::generateRsaKeys);

    // Подключение сигналов кнопок генерации ключей
    connect(ui->caesarGenerateButton, &QPushButton::clicked, this, &MainWindow::generateCaesarKey);
    connect(ui->beaufortGenerateButton, &QPushButton::clicked, this, &MainWindow::generateBeaufortKey);
    connect(ui->kuznechikGenerateButton, &QPushButton::clicked, this, &MainWindow::generateKuznechikKey);
    connect(ui->kuznechikVectorGenerateButton, &QPushButton::clicked, this, &MainWindow::generateKuznechikVector);
    connect(ui->aes256GenerateButton, &QPushButton::clicked, this, &MainWindow::generateAes256Key);
    connect(ui->blowfishGenerateButton, &QPushButton::clicked, this, &MainWindow::generateBlowfishKey);
    connect(ui->tripleDesGenerateButton, &QPushButton::clicked, this, &MainWindow::generateTripleDesKey);
    connect(ui->cast5GenerateButton, &QPushButton::clicked, this, &MainWindow::generateCast5Key);

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

    // Инициализация начального состояния
    onAlphabetChanged(0);
    onCipherChanged(0);
}

MainWindow::~MainWindow() {
    delete ui;
}

void MainWindow::onCipherChanged(int index) {
    ui->cipherInputStack->setCurrentIndex(index);
    
    // Определяем, требует ли шифр алфавит
    bool needsAlphabet = (index <= 2); // Caesar, Atbash, Beaufort требуют алфавит
    ui->alphabetSelector->setEnabled(needsAlphabet);
    if (!needsAlphabet) {
        ui->alphabetDisplay->setText("Данный шифр поддерживает кодирование любых символов");
    } else {
        updateAlphabetDisplay();
    }

    // Показываем rsaInputWidget только для RSA (индекс 4)
    QWidget* rsaWidget = ui->cipherInputStack->widget(4);
    if (index == 4) {
        rsaWidget->setVisible(true);
    } else {
        rsaWidget->setVisible(false);
    }

    // Настраиваем кнопки в зависимости от шифра
    if (index == 3) { // Kuznechik
        ui->encryptButton->setText("Шифровать/Дешифровать");
        ui->decryptButton->setVisible(false);
    } else {
        ui->encryptButton->setText("Зашифровать");
        ui->decryptButton->setVisible(true);
    }
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


    try {
        // Получить ключ и вектор в зависимости от шифра
        if (idx == 0) { // Caesar
            key = ui->caesarKeyInput->text();
            if (key.isEmpty()) {
                throw QString("Введите ключ для шифра Цезаря");
            }
        } else if (idx == 2) { // Beaufort
            key = ui->beaufortKeyInput->text();
            if (key.isEmpty()) {
                throw QString("Введите ключ для шифра Бофора");
            }
        } else if (idx == 3) { // Kuznechik
            key = ui->kuznechikKeyInput->text();
            vector = ui->kuznechikVectorInput->text();
            if (key.isEmpty() || vector.isEmpty()) {
                throw QString("Введите ключ и вектор для шифра Кузнечик");
            }
            // Для Кузнечика используем одну и ту же функцию для шифрования и дешифрования
            result = crypt(text);
            if (result.startsWith("Ошибка:")) {
                throw result;
            }
            ui->outputText->setPlainText(result);
            return; // Выходим, так как обработка уже завершена
        } else if (idx == 4) { // RSA
            if (rsaPublicKey.isEmpty() || rsaPrivateKey.isEmpty()) {
                generateRsaKeys();
            }
            key = rsaPublicKey;
            if (key.isEmpty()) {
                throw QString("Сгенерируйте ключи RSA");
            }
        } else if (idx >= 5) { // Современные шифры
            QLineEdit* keyInput = nullptr;
            QString cipherName;

            switch(idx) {
                case 5: // AES-256
                    keyInput = ui->aes256KeyInput;
                    cipherName = "AES-256";
                    break;
                case 6: // Blowfish
                    keyInput = ui->blowfishKeyInput;
                    cipherName = "Blowfish";
                    break;
                case 7: // 3DES
                    keyInput = ui->tripleDesKeyInput;
                    cipherName = "3DES";
                    break;
                case 8: // CAST5
                    keyInput = ui->cast5KeyInput;
                    cipherName = "CAST5";
                    break;
            }

            if (keyInput) {
                key = keyInput->text();
                if (key.isEmpty()) {
                    throw QString("Введите ключ для шифра " + cipherName);
                }
            }

        }

        result = std::invoke(cipherFuncs[idx], this, text, key, currentAlphabet);

        if (result.startsWith("Ошибка:")) {
            throw result;
        }

        ui->outputText->setPlainText(result);
    } catch (const QString& error) {
        QMessageBox::warning(this, "Ошибка", error);
    } catch (...) {
        QMessageBox::warning(this, "Ошибка", "Произошла неизвестная ошибка при шифровании");
    }
}

void MainWindow::decryptText() {
    int idx = ui->cipherSelector->currentIndex();
    QString text = ui->inputText->toPlainText();
    QString key;
    QString result;

    if (text.isEmpty()) {
        QMessageBox::warning(this, "Ошибка", "Введите текст для расшифровки.");
        return;
    }


    try {
        // Получаем ключ в зависимости от шифра
        if (idx == 0) { // Caesar
            key = ui->caesarKeyInput->text();
            if (key.isEmpty()) {
                throw QString("Введите ключ для расшифровки шифра Цезаря");
            }
            // Для расшифровки Caesar используем отрицательный сдвиг
            bool ok;
            int shift = key.toInt(&ok);
            if (!ok) {
                throw QString("Ключ шифра Цезаря должен быть числом");
            }
            key = QString::number(-shift);
            result = caesarEncrypt(text, key, currentAlphabet);
        }
        else if (idx == 1) { // Atbash
            // Atbash - самообратимый шифр
            result = atbashEncrypt(text, "", currentAlphabet);
        }
        else if (idx == 2) { // Beaufort
            // Beaufort - самообратимый шифр
            key = ui->beaufortKeyInput->text();
            if (key.isEmpty()) {
                throw QString("Введите ключ для расшифровки шифра Бофора");
            }
            result = beaufortEncrypt(text, key, currentAlphabet);
        }
        else if (idx == 3) { // Kuznechik
            // Для Кузнечика используем ту же функцию crypt
            key = ui->kuznechikKeyInput->text();
            QString vector = ui->kuznechikVectorInput->text();
            if (key.isEmpty() || vector.isEmpty()) {
                throw QString("Введите ключ и вектор для расшифровки шифра Кузнечик");
            }
            result = crypt(text);
        }
        else if (idx == 4) { // RSA
            key = ui->privateKeyInput->toPlainText();
            if (key.isEmpty()) {
                throw QString("Необходим приватный ключ для расшифровки RSA");
            }
            result = rsaDecrypt(text, key);
        }
        else if (idx >= 5) { // Современные шифры
            QLineEdit* keyInput = nullptr;
            QString cipherName;
            std::function<QString(const QString&, const QString&)> decryptFunc;

            switch(idx) {
                case 5: // AES-256
                    keyInput = ui->aes256KeyInput;
                    cipherName = "AES-256";
                    decryptFunc = std::bind(&MainWindow::aes256Decrypt, this, std::placeholders::_1, std::placeholders::_2);
                    break;
                case 6: // Blowfish
                    keyInput = ui->blowfishKeyInput;
                    cipherName = "Blowfish";
                    decryptFunc = std::bind(&MainWindow::blowfishDecrypt, this, std::placeholders::_1, std::placeholders::_2);
                    break;
                case 7: // 3DES
                    keyInput = ui->tripleDesKeyInput;
                    cipherName = "3DES";
                    decryptFunc = std::bind(&MainWindow::tripleDesDecrypt, this, std::placeholders::_1, std::placeholders::_2);
                    break;
                case 8: // CAST5
                    keyInput = ui->cast5KeyInput;
                    cipherName = "CAST5";
                    decryptFunc = std::bind(&MainWindow::cast5Decrypt, this, std::placeholders::_1, std::placeholders::_2);
                    break;
            }

            if (keyInput) {
                key = keyInput->text();
                if (key.isEmpty()) {
                    throw QString("Введите ключ для расшифровки " + cipherName);
                }
                result = decryptFunc(text, key);
            }
        }


        if (result.startsWith("Ошибка:")) {
            throw result;
        }

        ui->outputText->setPlainText(result);
    } catch (const QString& error) {
        QMessageBox::warning(this, "Ошибка", error);
    } catch (...) {
        QMessageBox::warning(this, "Ошибка", "Произошла неизвестная ошибка при расшифровке");
    }
}

void MainWindow::exportResult() {

    QString content = ui->outputText->toPlainText();
    if (content.isEmpty()) {
        QMessageBox::warning(this, "Ошибка", "Нет данных для экспорта.");

        return;
    }

    // Создаем и показываем диалог выбора формата
    ExportFormatDialog formatDialog(this);
    if (formatDialog.exec() != QDialog::Accepted) {
        return;
    }


    // Получаем выбранный формат
    QString format = formatDialog.getSelectedFormat();
    
    // Проверяем, что формат был выбран
    if (format.isEmpty()) {
        QMessageBox::warning(this, "Ошибка", "Формат экспорта не выбран.");
        return;
    }
    
    // Открываем диалог сохранения файла с соответствующим расширением
    QString fileFilter;

    if (format == "txt") {
        fileFilter = "Text Files (*.txt)";
    } else if (format == "html") {
        fileFilter = "HTML Files (*.html)";
    } else if (format == "json") {
        fileFilter = "JSON Files (*.json)";
    } else {
        QMessageBox::warning(this, "Ошибка", "Неподдерживаемый формат экспорта: " + format);
        return;
    }


    QString fileName = QFileDialog::getSaveFileName(this,
        "Сохранить результат",
        QString(),
        fileFilter);

    if (fileName.isEmpty()) {
        return;
    }


    // Добавляем расширение, если его нет
    if (!fileName.endsWith("." + format)) {
        fileName += "." + format;
    }

    // Создаем экспортер и экспортируем данные
    Exporter exporter;
    QString inputText = ui->inputText->toPlainText();
    QString outputText = ui->outputText->toPlainText();
    int cipherIndex = ui->cipherSelector->currentIndex();
    QString cipherName = cipherNames[cipherIndex];

    try {
        if (!exporter.exportData(fileName, format, inputText, outputText, cipherName)) {
            throw QString("Не удалось экспортировать данные в файл.");
        }
        QMessageBox::information(this, "Успех", "Данные успешно экспортированы в файл:\n" + fileName);
    } catch (const QString& error) {
        QMessageBox::critical(this, "Ошибка", error);
    } catch (...) {
        QMessageBox::critical(this, "Ошибка", "Произошла неизвестная ошибка при экспорте данных.");
    }
}

QString MainWindow::caesarEncrypt(const QString& text, const QString& key, const QString& alphabet) {

    bool ok;
    int shift = key.toInt(&ok);
    if (!ok) {
        return "Ошибка: Ключ должен быть числом";
    }

    QString result;
    for (QChar c : text) {
        int idx = alphabet.indexOf(c.toUpper());
        if (idx != -1) {
            int newIdx = (idx + shift) % alphabet.length();
            if (newIdx < 0) newIdx += alphabet.length();
            result += c.isUpper() ? alphabet[newIdx] : alphabet[newIdx].toLower();
        } else {
            result += c;
        }
    }
    return result;
}

QString MainWindow::atbashEncrypt(const QString& text, const QString& key, const QString& alphabet) {
    Q_UNUSED(key);

    QString result;
    for (QChar c : text) {
        int idx = alphabet.indexOf(c.toUpper());
        if (idx != -1) {
            int newIdx = alphabet.length() - 1 - idx;
            result += c.isUpper() ? alphabet[newIdx] : alphabet[newIdx].toLower();
        } else {
            result += c;
        }
    }
    return result;
}

QString MainWindow::beaufortEncrypt(const QString& text, const QString& key, const QString& alphabet) {

    if (key.isEmpty()) {
        return "Ошибка: Ключ не может быть пустым";
    }

    QString result;
    int keyIdx = 0;

    for (QChar c : text) {
        int textIdx = alphabet.indexOf(c.toUpper());
        if (textIdx != -1) {
            int keyCharIdx = alphabet.indexOf(key[keyIdx % key.length()].toUpper());
            if (keyCharIdx == -1) {
                return "Ошибка: Ключ содержит символы не из алфавита";
            }

            int newIdx = (keyCharIdx - textIdx + alphabet.length()) % alphabet.length();
            result += c.isUpper() ? alphabet[newIdx] : alphabet[newIdx].toLower();
            keyIdx++;
        } else {
            result += c;
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
    if (key.isEmpty()) {
        return "Ошибка: Отсутствует публичный ключ";
    }

    QCA::PublicKey pubKey = QCA::PublicKey::fromPEM(key);
    if (pubKey.isNull()) {
        return "Ошибка: Неверный формат публичного ключа";
    }

    QCA::SecureArray plainText(text.toUtf8());
    QCA::SecureArray cipherText = pubKey.encrypt(plainText, QCA::EME_PKCS1_OAEP);
    if (cipherText.isEmpty()) {
        return "Ошибка: Не удалось зашифровать текст";
    }

    return QString::fromLatin1(cipherText.toByteArray().toBase64());
}

QString MainWindow::aes256Encrypt(const QString& text, const QString& key, const QString& alphabet) {
    Q_UNUSED(alphabet);
    if (key.isEmpty()) {
        return "Ошибка: Ключ не может быть пустым";
    }

    QCA::Hash hash("sha256");
    hash.update(key.toUtf8());
    QCA::SymmetricKey symKey(hash.final());
    QCA::InitializationVector iv(16);

    QCA::Cipher cipher(QString("aes256"), QCA::Cipher::CBC,
                      QCA::Cipher::DefaultPadding, QCA::Encode,
                      symKey, iv);

    QCA::SecureArray encrypted = cipher.process(text.toUtf8());
    if (!cipher.ok()) {
        return "Ошибка: Не удалось зашифровать текст";
    }

    QByteArray result;
    result.append(iv.toByteArray());
    result.append(encrypted.toByteArray());
    return QString::fromLatin1(result.toBase64());
}

QString MainWindow::blowfishEncrypt(const QString& text, const QString& key, const QString& alphabet) {
    Q_UNUSED(alphabet);
    if (key.isEmpty()) {
        return "Ошибка: Ключ не может быть пустым";
    }

    QCA::Hash hashObj("sha256");
    hashObj.update(key.toUtf8());
    QCA::SymmetricKey symKey(hashObj.final());
    QCA::InitializationVector iv(8);

    QCA::Cipher cipher(QString("blowfish"), QCA::Cipher::CBC,
                      QCA::Cipher::DefaultPadding, QCA::Encode,
                      symKey, iv);

    QCA::SecureArray encrypted = cipher.process(text.toUtf8());
    if (!cipher.ok()) {
        return "Ошибка: Не удалось зашифровать текст";
    }

    QByteArray result;
    result.append(iv.toByteArray());
    result.append(encrypted.toByteArray());
    return QString::fromLatin1(result.toBase64());
}

QString MainWindow::tripleDesEncrypt(const QString& text, const QString& key, const QString& alphabet) {
    Q_UNUSED(alphabet);

    if (key.isEmpty()) {
        return "Ошибка: Ключ не может быть пустым";
    }

    QCA::Hash hashObj("sha256");
    hashObj.update(key.toUtf8());
    QCA::SymmetricKey symKey(hashObj.final());
    QCA::InitializationVector iv(8);

    QCA::Cipher cipher(QString("3des"), QCA::Cipher::CBC,
                      QCA::Cipher::DefaultPadding, QCA::Encode,
                      symKey, iv);

    QCA::SecureArray encrypted = cipher.process(text.toUtf8());
    if (!cipher.ok()) {
        return "Ошибка: Не удалось зашифровать текст";
    }

    QByteArray result;
    result.append(iv.toByteArray());
    result.append(encrypted.toByteArray());
    return QString::fromLatin1(result.toBase64());
}

QString MainWindow::cast5Encrypt(const QString& text, const QString& key, const QString& alphabet) {
    Q_UNUSED(alphabet);
    if (key.isEmpty()) {
        return "Ошибка: Ключ не может быть пустым";
    }

    QCA::Hash hashObj("sha256");
    hashObj.update(key.toUtf8());
    QCA::SymmetricKey symKey(hashObj.final());
    QCA::InitializationVector iv(8);

    QCA::Cipher cipher(QString("cast5-cbc"), QCA::Cipher::CBC,
                      QCA::Cipher::DefaultPadding, QCA::Encode,
                      symKey, iv);

    QCA::SecureArray encrypted = cipher.process(text.toUtf8());
    if (!cipher.ok()) {
        return "Ошибка: Не удалось зашифровать текст";
    }

    QByteArray result;
    result.append(iv.toByteArray());
    result.append(encrypted.toByteArray());
    return QString::fromLatin1(result.toBase64());
}

// Реализации функций расшифровки
QString MainWindow::rsaDecrypt(const QString& text, const QString& key) {
    if (key.isEmpty()) {
        return "Ошибка: Отсутствует приватный ключ";
    }

    QCA::PrivateKey privKey = QCA::PrivateKey::fromPEM(key);
    if (privKey.isNull()) {
        return "Ошибка: Неверный формат приватного ключа";
    }

    QByteArray cipherText = QByteArray::fromBase64(text.toLatin1());
    QCA::SecureArray encryptedData(cipherText);
    QCA::SecureArray decryptedData;

    if (!privKey.decrypt(encryptedData, &decryptedData, QCA::EME_PKCS1_OAEP)) {
        return "Ошибка: Не удалось расшифровать текст";
    }

    return QString::fromUtf8(decryptedData.toByteArray());
}

QString MainWindow::aes256Decrypt(const QString& text, const QString& key) {
    if (key.isEmpty()) {
        return "Ошибка: Ключ не может быть пустым";
    }

    QByteArray combined = QByteArray::fromBase64(text.toLatin1());
    if (combined.size() < 16) {
        return "Ошибка: Неверный формат зашифрованных данных";
    }

    QCA::InitializationVector iv(combined.left(16));
    QByteArray cipherText = combined.mid(16);

    QCA::Hash hash("sha256");
    hash.update(key.toUtf8());
    QCA::SymmetricKey symKey(hash.final());

    QCA::Cipher cipher(QString("aes256"), QCA::Cipher::CBC,
                      QCA::Cipher::DefaultPadding, QCA::Decode,
                      symKey, iv);

    QCA::SecureArray decrypted = cipher.process(cipherText);
    if (!cipher.ok()) {
        return "Ошибка: Не удалось расшифровать текст";
    }

    return QString::fromUtf8(decrypted.toByteArray());
}

QString MainWindow::blowfishDecrypt(const QString& text, const QString& key) {
    if (key.isEmpty()) {
        return "Ошибка: Ключ не может быть пустым";
    }

    QByteArray combined = QByteArray::fromBase64(text.toLatin1());
    if (combined.size() < 8) {
        return "Ошибка: Неверный формат зашифрованных данных";
    }

    QCA::InitializationVector iv(combined.left(8));
    QByteArray cipherText = combined.mid(8);

    QCA::Hash hashObj("sha256");
    hashObj.update(key.toUtf8());
    QCA::SymmetricKey symKey(hashObj.final());

    QCA::Cipher cipher(QString("blowfish"), QCA::Cipher::CBC,
                      QCA::Cipher::DefaultPadding, QCA::Decode,
                      symKey, iv);

    QCA::SecureArray decrypted = cipher.process(cipherText);
    if (!cipher.ok()) {
        return "Ошибка: Не удалось расшифровать текст";
    }

    return QString::fromUtf8(decrypted.toByteArray());
}

QString MainWindow::tripleDesDecrypt(const QString& text, const QString& key) {
    if (key.isEmpty()) {
        return "Ошибка: Ключ не может быть пустым";
    }

    QByteArray combined = QByteArray::fromBase64(text.toLatin1());
    if (combined.size() < 8) {
        return "Ошибка: Неверный формат зашифрованных данных";
    }

    QCA::InitializationVector iv(combined.left(8));
    QByteArray cipherText = combined.mid(8);

    QCA::Hash hashObj("sha256");
    hashObj.update(key.toUtf8());
    QCA::SymmetricKey symKey(hashObj.final());

    QCA::Cipher cipher(QString("3des"), QCA::Cipher::CBC,
                      QCA::Cipher::DefaultPadding, QCA::Decode,
                      symKey, iv);

    QCA::SecureArray decrypted = cipher.process(cipherText);
    if (!cipher.ok()) {
        return "Ошибка: Не удалось расшифровать текст";
    }

    return QString::fromUtf8(decrypted.toByteArray());
}

QString MainWindow::cast5Decrypt(const QString& text, const QString& key) {
    if (key.isEmpty()) {
        return "Ошибка: Ключ не может быть пустым";
    }

    QByteArray combined = QByteArray::fromBase64(text.toLatin1());
    if (combined.size() < 8) {
        return "Ошибка: Неверный формат зашифрованных данных";
    }

    QCA::InitializationVector iv(combined.left(8));
    QByteArray cipherText = combined.mid(8);

    QCA::Hash hashObj("sha256");
    hashObj.update(key.toUtf8());
    QCA::SymmetricKey symKey(hashObj.final());

    QCA::Cipher cipher(QString("cast5"), QCA::Cipher::CBC,
                      QCA::Cipher::DefaultPadding, QCA::Decode,
                      symKey, iv);

    QCA::SecureArray decrypted = cipher.process(cipherText);
    if (!cipher.ok()) {
        return "Ошибка: Не удалось расшифровать текст";
    }

    return QString::fromUtf8(decrypted.toByteArray());
}

// Функции генерации ключей
void MainWindow::generateCaesarKey() {
    int key = QRandomGenerator::global()->bounded(1, 26);
    ui->caesarKeyInput->setText(QString::number(key));
}

void MainWindow::generateBeaufortKey() {
    QString alphabet = currentAlphabet;
    int length = QRandomGenerator::global()->bounded(3, 8); // Длина ключа от 3 до 7 символов
    QString key;
    for(int i = 0; i < length; i++) {
        int index = QRandomGenerator::global()->bounded(alphabet.length());
        key += alphabet[index];
    }
    ui->beaufortKeyInput->setText(key);
}

void MainWindow::generateKuznechikKey() {
    QString key;
    // Генерируем 64 hex-символа (32 байта)
    for(int i = 0; i < 64; i++) {
        key += QString::number(QRandomGenerator::global()->bounded(16), 16);
    }
    ui->kuznechikKeyInput->setText(key.toLower());
}

void MainWindow::generateKuznechikVector() {
    QString vector;
    // Генерируем 16 hex-символов (8 байт)
    for(int i = 0; i < 16; i++) {
        vector += QString::number(QRandomGenerator::global()->bounded(16), 16);
    }
    ui->kuznechikVectorInput->setText(vector.toLower());
}

void MainWindow::generateAes256Key() {
    QCA::SecureArray secureKey = QCA::Random::randomArray(32);
    QByteArray key = secureKey.toByteArray();
    ui->aes256KeyInput->setText(QString::fromLatin1(key.toBase64()));
}

void MainWindow::generateBlowfishKey() {
    QCA::SecureArray secureKey = QCA::Random::randomArray(16);
    QByteArray key = secureKey.toByteArray();
    ui->blowfishKeyInput->setText(QString::fromLatin1(key.toBase64()));
}

void MainWindow::generateTripleDesKey() {
    QCA::SecureArray secureKey = QCA::Random::randomArray(24);
    QByteArray key = secureKey.toByteArray();
    ui->tripleDesKeyInput->setText(QString::fromLatin1(key.toBase64()));
}

void MainWindow::generateCast5Key() {
    QCA::SecureArray secureKey = QCA::Random::randomArray(16);
    QByteArray key = secureKey.toByteArray();
    ui->cast5KeyInput->setText(QString::fromLatin1(key.toBase64()));

}
