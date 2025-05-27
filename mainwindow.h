#pragma once
#include <QMainWindow>
#include <QVector>
#include <functional>
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
    void exportResult();

private:
    Ui::MainWindow* ui;
    QVector<QString> cipherNames;
    QVector<std::function<QString(const QString&, const QString&, const QString&)>> cipherFuncs;
    QString currentAlphabet;
    void updateAlphabetDisplay();
};
