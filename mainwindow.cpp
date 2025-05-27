#include "mainwindow.h"
#include "ui_MainWindow.h"
#include "exporter.h"
#include <QFileDialog>
#include <QMessageBox>
#include <QInputDialog>

MainWindow::MainWindow(QWidget* parent)
    : QMainWindow(parent), ui(new Ui::MainWindow) {
    ui->setupUi(this);

    // Имена шифров и функции
    cipherNames = {"Caesar", "Atbash", "Beaufort"};
    cipherFuncs = { caesarEncrypt, atbashEncrypt, beaufortEncrypt };
    for (const auto& name : cipherNames) {
        ui->cipherSelector->addItem(name);
    }

    // Алфавиты
    ui->alphabetSelector->addItem("English");
    ui->alphabetSelector->addItem("Russian");
    ui->alphabetSelector->addItem("Custom...");

    connect(ui->alphabetSelector, SIGNAL(currentIndexChanged(int)), this, SLOT(onAlphabetChanged(int)));
    connect(ui->encryptButton, &QPushButton::clicked, this, &MainWindow::encryptText);
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
    QString result = cipherFuncs[idx](text, key, currentAlphabet);
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
    bool ok = Exporter::exportToFile(
        filename,
        ui->inputText->toPlainText(),
        ui->outputText->toPlainText()
        );
    if (!ok) {
        QMessageBox::warning(this, "Ошибка", "Не удалось сохранить файл.");
    } else {
        QMessageBox::information(this, "Готово", "Файл сохранен.");
    }
}
