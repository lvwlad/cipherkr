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
    void onCipherChanged(int index); // Added
    void encryptText();
    void decryptText();
    void exportResult();
    void generateRsaKeys();

private:
    Ui::MainWindow* ui;
    QVector<QString> cipherNames;
    using CipherFunc = std::function<QString(const QString&, const QString&, const QString&)>; // Simplified
    QVector<CipherFunc> cipherFuncs;
    QString currentAlphabet;
    QString rsaPublicKey;
    QString rsaPrivateKey;
    void updateAlphabetDisplay();
};
