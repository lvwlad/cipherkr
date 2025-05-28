#pragma once
#include <QMainWindow>
#include <QVector>
#include <functional>
#include <variant>
#include "ciphers.h"

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow {
    Q_OBJECT
public:
    explicit MainWindow(QWidget* parent = nullptr);
    ~MainWindow();

private slots:
    void onAlphabetChanged(int index);
    void encryptText();
    void decryptText();
    void exportResult();
    void generateRsaKeys(); // Новая функция для генерации ключей

private:
    Ui::MainWindow* ui;
    QVector<QString> cipherNames;
    using CipherFunc = std::variant<
        std::function<QString(const QString&, const QString&, const QString&)>,
        std::function<QString(const QString&, QString&, QString&)>
        >;
    QVector<CipherFunc> cipherFuncs;
    QString currentAlphabet;
    QString rsaPublicKey;   // Хранит публичный ключ
    QString rsaPrivateKey;  // Хранит приватный ключ
    void updateAlphabetDisplay();
};
