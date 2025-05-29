#include "mainwindow.h"
#include "ui_MainWindow.h"
#include "exporter.h"
#include <QFileDialog>
#include <QMessageBox>
#include <QInputDialog>
#include <QtCrypto/QtCrypto>

MainWindow::MainWindow(QWidget* parent)
    : QMainWindow(parent), ui(new Ui::MainWindow) {
    ui->setupUi(this);

    // Имена шифров и функции
    cipherNames = {"Caesar", "Atbash", "Beaufort", "Kuznechik", "RSA", "AES-256", "Blowfish", "3DES", "CAST5"};
    cipherFuncs = {
        caesarEncrypt,
        atbashEncrypt,
        beaufortEncrypt,
        kuznechikEncrypt,
        rsaEncrypt,
        aes256Encrypt,
        blowfishEncrypt,
        tripleDesEncrypt,
        cast5Encrypt
    };

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
    ui->decryptButton->setEnabled(index == 4 || index == 5 || index == 6 || index == 7 || index == 8);
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

void MainWindow::encryptText() {
    int idx = ui->cipherSelector->currentIndex();
    QString text = ui->inputText->toPlainText();
    QString key;
    QString result;

    if (text.isEmpty()) {
        QMessageBox::warning(this, "Ошибка", "Введите текст для шифрования.");
        return;
    }

    // Получить ключ в зависимости от шифра
    if (idx == 0) { // Caesar
        key = ui->caesarKeyInput->text();
    } else if (idx == 2) { // Beaufort
        key = ui->beaufortKeyInput->text();
    } else if (idx == 3) { // Kuznechik
        key = ui->kuznechikKeyInput->text();
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

    result = cipherFuncs[idx](text, key, currentAlphabet);
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
    QString result;

    if (base64Text.isEmpty()) {
        QMessageBox::warning(this, "Ошибка", "Введите текст для расшифровки.");
        return;
    }

    if (idx == 4) { // RSA
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
        QMessageBox::warning(this, "Ошибка", "Расшифровка доступна только для RSA, AES-256, Blowfish, 3DES и CAST5.");
        return;
    }

    if (result.startsWith("Ошибка:")) {
        QMessageBox::warning(this, "Ошибка", result);
        return;
    }
    ui->outputText->setPlainText(result);
}

void MainWindow::exportResult() {
    QString filename = QFileDialog::getSaveFileName(
        this,
        "Сохранить результат",
        QString(),
        "Text Files (*.txt);;HTML Files (*.html);;LaTeX Files (*.tex)"
        );
    if (filename.isEmpty()) {
        return;
    }

    // Определяем формат по расширению файла
    QString format = "txt";
    if (filename.endsWith(".html")) format = "html";
    else if (filename.endsWith(".tex")) format = "pdf";

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
        QMessageBox::information(this, "Готово", "Файл сохранён. Для PDF скомпилируйте .tex файл с помощью latexmk.");
    }
}
