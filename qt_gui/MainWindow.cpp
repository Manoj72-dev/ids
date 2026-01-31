#include "MainWindow.h"
#include "ui_MainWindow.h"

#include <QTableWidget>
#include <QHeaderView>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QPushButton>
#include <QLabel>
#include <QTextEdit>
#include <QTimer>
#include <QTime>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent),
      ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    QWidget *central = new QWidget(this);
    QVBoxLayout *mainLayout = new QVBoxLayout(central);

    statusLabel = new QLabel("STATUS: IDLE");
    mainLayout->addWidget(statusLabel);

    alertTable = new QTableWidget(0, 2);
    alertTable->setHorizontalHeaderLabels({"Time", "Alert"});
    alertTable->horizontalHeader()->setStretchLastSection(true);
    mainLayout->addWidget(alertTable);

    logViewer = new QTextEdit();
    logViewer->setReadOnly(true);
    mainLayout->addWidget(logViewer);

    QHBoxLayout *btnLayout = new QHBoxLayout();

    startButton = new QPushButton("Start IDS");
    stopButton  = new QPushButton("Stop IDS");
    stopButton->setEnabled(false);

    btnLayout->addWidget(startButton);
    btnLayout->addWidget(stopButton);
    mainLayout->addLayout(btnLayout);

    setCentralWidget(central);

    connect(startButton, &QPushButton::clicked,
            this, &MainWindow::startIDS);

    connect(stopButton, &QPushButton::clicked,
            this, &MainWindow::stopIDS);

    pollTimer = new QTimer(this);
    connect(pollTimer, &QTimer::timeout,
            this, &MainWindow::pollAlerts);
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::startIDS()
{
    statusLabel->setText("STATUS: RUNNING");
    startButton->setEnabled(false);
    stopButton->setEnabled(true);

    logViewer->append("IDS started");
    alertTable->setRowCount(0);

    pollTimer->start(1000);
}

void MainWindow::stopIDS()
{
    statusLabel->setText("STATUS: STOPPED");
    startButton->setEnabled(true);
    stopButton->setEnabled(false);

    logViewer->append("IDS stopped");

    pollTimer->stop();
}

void MainWindow::pollAlerts()
{
    QString alert = "Sample alert";

    int row = alertTable->rowCount();
    alertTable->insertRow(row);
    alertTable->setItem(row, 0,
        new QTableWidgetItem(QTime::currentTime().toString()));
    alertTable->setItem(row, 1,
        new QTableWidgetItem(alert));

    logViewer->append("Alert received: " + alert);
}
