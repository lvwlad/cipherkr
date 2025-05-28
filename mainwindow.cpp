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
    cipherNames = {"Caesar", "Atbash", "Beaufort", "Kuznechik", "RSA"};
    cipherFuncs = {
        caesarEncrypt,
        atbashEncrypt,
        beaufortEncrypt,
        kuznechikEncrypt,
        rsaEncrypt
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

// Остальной код остаётся без изменений
void MainWindow::onCipherChanged(int index) {
    ui->cipherInputStack->setCurrentIndex(index);
    ui->decryptButton->setEnabled(index == 4);
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
    } // Atbash (idx == 1) не требует ключа

    result = cipherFuncs[idx](text, key, currentAlphabet);
    ui->outputText->setPlainText(result);
}

void MainWindow::decryptText() {
    if (ui->cipherSelector->currentIndex() != 4) {
        QMessageBox::warning(this, "Ошибка", "Расшифровка доступна только для RSA.");
        return;
    }

    QString base64Text = ui->inputText->toPlainText();
    QString privateKey = ui->privateKeyInput->toPlainText();
    if (privateKey.isEmpty()) {
        QMessageBox::warning(this, "Ошибка", "Введите приватный ключ для расшифровки.");
        return;
    }
    QString result = rsaDecrypt(base64Text, privateKey);
    ui->outputText->setPlainText(result);
}

void MainWindow::exportResult() {
    QString filename = QFileDialog::getSaveFileName(
        this,
        "Сохранить результат",
        QString(),
        "Text Files (*.txt)"
        );
    if (filename.isEmpty()) {
        return;
    }
    bool ok;
    if (ui->cipherSelector->currentIndex() == 4) { // RSA
        ok = Exporter::exportToFile(
            filename,
            ui->inputText->toPlainText(),
            ui->outputText->toPlainText(),
            rsaPublicKey,
            rsaPrivateKey
            );
    } else {
        ok = Exporter::exportToFile(
            filename,
            ui->inputText->toPlainText(),
            ui->outputText->toPlainText()
            );
    }
    if (!ok) {
        QMessageBox::warning(this, "Ошибка", "Не удалось сохранить файл.");
    } else {
        QMessageBox::information(this, "Готово", "Файл сохранен.");
    }
}
