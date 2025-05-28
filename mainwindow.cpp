#include "mainwindow.h"
#include "ui_MainWindow.h"
#include "exporter.h"
#include <QFileDialog>
#include <QMessageBox>
#include <QInputDialog>
#include <QtCrypto/QtCrypto>
#include <variant>

MainWindow::MainWindow(QWidget* parent)
    : QMainWindow(parent), ui(new Ui::MainWindow) {
    ui->setupUi(this);

    // Имена шифров и функции
    cipherNames = {"Caesar", "Atbash", "Beaufort", "Kuznechik", "RSA"};
    cipherFuncs = {
        std::function<QString(const QString&, const QString&, const QString&)>(caesarEncrypt),
        std::function<QString(const QString&, const QString&, const QString&)>(atbashEncrypt),
        std::function<QString(const QString&, const QString&, const QString&)>(beaufortEncrypt),
        std::function<QString(const QString&, const QString&, const QString&)>(kuznechikEncrypt),
        std::function<QString(const QString&, const QString&, const QString&)>(rsaEncrypt)
    };

    for (const auto& name : cipherNames) {
        ui->cipherSelector->addItem(name);
    }

    // Алфавиты
    ui->alphabetSelector->addItem("English");
    ui->alphabetSelector->addItem("Russian");
    ui->alphabetSelector->addItem("Custom...");

    connect(ui->alphabetSelector, SIGNAL(currentIndexChanged(int)), this, SLOT(onAlphabetChanged(int)));
    connect(ui->encryptButton, &QPushButton::clicked, this, &MainWindow::encryptText);
    connect(ui->decryptButton, &QPushButton::clicked, this, &MainWindow::decryptText);
    connect(ui->exportButton, &QPushButton::clicked, this, &MainWindow::exportResult);
    connect(ui->generateKeysButton, &QPushButton::clicked, this, &MainWindow::generateRsaKeys);

    // Инициализация QCA
    static QCA::Initializer init;

    onAlphabetChanged(0);
}

MainWindow::~MainWindow() {
    delete ui;
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
    QCA::PrivateKey privateKey = keyGen.createRSA(2048); // Генерация ключа длиной 2048 бит
    if (privateKey.isNull()) {
        QMessageBox::warning(this, "Ошибка", "Не удалось сгенерировать ключи.");
        return;
    }
    QCA::PublicKey publicKey = privateKey.toPublicKey();
    rsaPublicKey = publicKey.toPEM();
    rsaPrivateKey = privateKey.toPEM();
}

void MainWindow::encryptText() {
    int idx = ui->cipherSelector->currentIndex();
    QString text = ui->inputText->toPlainText();
    QString key = ui->keyInput->text();
    QString result;

    if (idx == 4) { // RSA
        // Генерируем ключи, если их ещё нет
        if (rsaPublicKey.isEmpty() || rsaPrivateKey.isEmpty()) {
            generateRsaKeys();
        }
        // Используем сгенерированный публичный ключ
        result = std::get<0>(cipherFuncs[idx])(text, rsaPublicKey, currentAlphabet);
        // Показываем ключи и результат
        ui->outputText->setPlainText(result + "\n\nPublic Key:\n" + rsaPublicKey + "\nPrivate Key:\n" + rsaPrivateKey);
    } else {
        result = std::get<0>(cipherFuncs[idx])(text, key, currentAlphabet);
        ui->outputText->setPlainText(result);
    }
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
