/********************************************************************************
** Form generated from reading UI file 'MainWindow.ui'
**
** Created by: Qt User Interface Compiler version 6.10.1
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_MAINWINDOW_H
#define UI_MAINWINDOW_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QComboBox>
#include <QtWidgets/QFormLayout>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QHeaderView>
#include <QtWidgets/QLabel>
#include <QtWidgets/QMainWindow>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QStackedWidget>
#include <QtWidgets/QTableWidget>
#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QWidget>

QT_BEGIN_NAMESPACE

class Ui_MainWindow
{
public:
    QWidget *centralwidget;
    QVBoxLayout *verticalLayout;
    QWidget *topbar;
    QHBoxLayout *horizontalLayout;
    QLabel *labelStatus;
    QComboBox *comboInterface;
    QPushButton *btnStop;
    QPushButton *btnStart;
    QWidget *MainBody;
    QHBoxLayout *horizontalLayout_2;
    QWidget *sidebar;
    QFormLayout *formLayout;
    QPushButton *btnPacket;
    QPushButton *pushButton_2;
    QPushButton *pushButton_4;
    QPushButton *pushButton_3;
    QStackedWidget *infoWidget;
    QWidget *widget;
    QWidget *page_5;
    QWidget *page_6;
    QWidget *page_7;
    QWidget *PacketsPage;
    QVBoxLayout *verticalLayout_3;
    QTableWidget *tableWidget;

    void setupUi(QMainWindow *MainWindow)
    {
        if (MainWindow->objectName().isEmpty())
            MainWindow->setObjectName("MainWindow");
        MainWindow->resize(1000, 585);
        MainWindow->setMinimumSize(QSize(1000, 500));
        MainWindow->setMaximumSize(QSize(1000, 585));
        MainWindow->setStyleSheet(QString::fromUtf8(""));
        centralwidget = new QWidget(MainWindow);
        centralwidget->setObjectName("centralwidget");
        centralwidget->setStyleSheet(QString::fromUtf8(""));
        verticalLayout = new QVBoxLayout(centralwidget);
        verticalLayout->setSpacing(0);
        verticalLayout->setObjectName("verticalLayout");
        verticalLayout->setContentsMargins(11, 11, 11, 11);
        topbar = new QWidget(centralwidget);
        topbar->setObjectName("topbar");
        topbar->setMinimumSize(QSize(0, 55));
        topbar->setMaximumSize(QSize(16777215, 55));
        topbar->setStyleSheet(QString::fromUtf8(""));
        horizontalLayout = new QHBoxLayout(topbar);
        horizontalLayout->setObjectName("horizontalLayout");
        labelStatus = new QLabel(topbar);
        labelStatus->setObjectName("labelStatus");
        labelStatus->setMaximumSize(QSize(200, 16777215));

        horizontalLayout->addWidget(labelStatus);

        comboInterface = new QComboBox(topbar);
        comboInterface->setObjectName("comboInterface");

        horizontalLayout->addWidget(comboInterface);

        btnStop = new QPushButton(topbar);
        btnStop->setObjectName("btnStop");
        btnStop->setMaximumSize(QSize(100, 16777215));
        btnStop->setLayoutDirection(Qt::LayoutDirection::RightToLeft);

        horizontalLayout->addWidget(btnStop);

        btnStart = new QPushButton(topbar);
        btnStart->setObjectName("btnStart");
        btnStart->setMinimumSize(QSize(0, 0));
        btnStart->setMaximumSize(QSize(100, 16777215));
        btnStart->setLayoutDirection(Qt::LayoutDirection::RightToLeft);

        horizontalLayout->addWidget(btnStart);


        verticalLayout->addWidget(topbar);

        MainBody = new QWidget(centralwidget);
        MainBody->setObjectName("MainBody");
        MainBody->setStyleSheet(QString::fromUtf8(""));
        horizontalLayout_2 = new QHBoxLayout(MainBody);
        horizontalLayout_2->setSpacing(7);
        horizontalLayout_2->setObjectName("horizontalLayout_2");
        horizontalLayout_2->setContentsMargins(0, 11, 11, 11);
        sidebar = new QWidget(MainBody);
        sidebar->setObjectName("sidebar");
        sidebar->setMinimumSize(QSize(150, 508));
        sidebar->setMaximumSize(QSize(150, 16777215));
        sidebar->setFocusPolicy(Qt::FocusPolicy::NoFocus);
        sidebar->setStyleSheet(QString::fromUtf8(""));
        formLayout = new QFormLayout(sidebar);
        formLayout->setObjectName("formLayout");
        formLayout->setContentsMargins(11, 11, -1, 11);
        btnPacket = new QPushButton(sidebar);
        btnPacket->setObjectName("btnPacket");

        formLayout->setWidget(0, QFormLayout::ItemRole::FieldRole, btnPacket);

        pushButton_2 = new QPushButton(sidebar);
        pushButton_2->setObjectName("pushButton_2");

        formLayout->setWidget(1, QFormLayout::ItemRole::FieldRole, pushButton_2);

        pushButton_4 = new QPushButton(sidebar);
        pushButton_4->setObjectName("pushButton_4");

        formLayout->setWidget(2, QFormLayout::ItemRole::FieldRole, pushButton_4);

        pushButton_3 = new QPushButton(sidebar);
        pushButton_3->setObjectName("pushButton_3");

        formLayout->setWidget(3, QFormLayout::ItemRole::FieldRole, pushButton_3);


        horizontalLayout_2->addWidget(sidebar);

        infoWidget = new QStackedWidget(MainBody);
        infoWidget->setObjectName("infoWidget");
        infoWidget->setStyleSheet(QString::fromUtf8(""));
        widget = new QWidget();
        widget->setObjectName("widget");
        infoWidget->addWidget(widget);
        page_5 = new QWidget();
        page_5->setObjectName("page_5");
        infoWidget->addWidget(page_5);
        page_6 = new QWidget();
        page_6->setObjectName("page_6");
        infoWidget->addWidget(page_6);
        page_7 = new QWidget();
        page_7->setObjectName("page_7");
        infoWidget->addWidget(page_7);
        PacketsPage = new QWidget();
        PacketsPage->setObjectName("PacketsPage");
        PacketsPage->setStyleSheet(QString::fromUtf8(""));
        verticalLayout_3 = new QVBoxLayout(PacketsPage);
        verticalLayout_3->setObjectName("verticalLayout_3");
        tableWidget = new QTableWidget(PacketsPage);
        tableWidget->setObjectName("tableWidget");

        verticalLayout_3->addWidget(tableWidget);

        infoWidget->addWidget(PacketsPage);

        horizontalLayout_2->addWidget(infoWidget);


        verticalLayout->addWidget(MainBody);

        MainWindow->setCentralWidget(centralwidget);

        retranslateUi(MainWindow);

        infoWidget->setCurrentIndex(4);


        QMetaObject::connectSlotsByName(MainWindow);
    } // setupUi

    void retranslateUi(QMainWindow *MainWindow)
    {
        MainWindow->setWindowTitle(QCoreApplication::translate("MainWindow", "MainWindow", nullptr));
        labelStatus->setText(QCoreApplication::translate("MainWindow", "IDS Status", nullptr));
        btnStop->setText(QCoreApplication::translate("MainWindow", "Start", nullptr));
        btnStart->setText(QCoreApplication::translate("MainWindow", "Stop", nullptr));
        btnPacket->setText(QCoreApplication::translate("MainWindow", "Packets", nullptr));
        pushButton_2->setText(QCoreApplication::translate("MainWindow", "PushButton", nullptr));
        pushButton_4->setText(QCoreApplication::translate("MainWindow", "PushButton", nullptr));
        pushButton_3->setText(QCoreApplication::translate("MainWindow", "PushButton", nullptr));
    } // retranslateUi

};

namespace Ui {
    class MainWindow: public Ui_MainWindow {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_MAINWINDOW_H
