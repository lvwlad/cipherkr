#include "mainwindow.h"
#include "ui_MainWindow.h"
#include "exporter.h"
#include <QFileDialog>
#include <QMessageBox>
#include <QInputDialog>
#include <variant>
#include "ciphers.h"

MainWindow::MainWindow(QWidget* parent)
    : QMainWindow(parent), ui(new Ui::MainWindow) {
    ui->setupUi(this);

    // Имена шифров и функции
    cipherNames = {"Caesar", "Atbash", "Beaufort", "Kuznechik", "RSA"};
    cipherFuncs = QVector<std::variant<std::function<QString(const QString&, const QString&, const QString&)>,
                                       std::function<QString(const QString&, QString&, QString&)> > > {
        std::function<QString(const QString&, const QString&, const QString&)>(caesarEncrypt),
        std::function<QString(const QString&, const QString&, const QString&)>(atbashEncrypt),
        std::function<QString(const QString&, const QString&, const QString&)>(beaufortEncrypt),
        std::function<QString(const QString&, const QString&, const QString&)>(kuznechikEncrypt),
        std::function<QString(const QString&, QString&, QString&)>(
            [this](const QString& text, QString& outPublicKey, QString& outPrivateKey) {
                return rsaEncrypt(text, outPublicKey, outPrivateKey);
            }
            )
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

void MainWindow::encryptText() {
    int idx = ui->cipherSelector->currentIndex();
    QString text = ui->inputText->toPlainText();
    QString key = ui->keyInput->text();
    QString result;

    if (idx == 4) { // RSA
        result = std::get<1>(cipherFuncs[idx])(text, rsaPublicKey, rsaPrivateKey);
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
