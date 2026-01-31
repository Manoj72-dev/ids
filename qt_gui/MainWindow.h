#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class QLabel;
class QPushButton;
class QTableWidget;
class QTextEdit;
class QTimer;

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void startIDS();
    void stopIDS();
    void pollAlerts();

private:
    Ui::MainWindow *ui;

    QLabel *statusLabel;
    QPushButton *startButton;
    QPushButton *stopButton;
    QTableWidget *alertTable;
    QTextEdit *logViewer;
    QTimer *pollTimer;
};

#endif
