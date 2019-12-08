/********************************************************************************
** Form generated from reading UI file 'mainwindow.ui'
**
** Created by: Qt User Interface Compiler version 5.12.6
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_MAINWINDOW_H
#define UI_MAINWINDOW_H

#include <QtCore/QVariant>
#include <QtWidgets/QAction>
#include <QtWidgets/QApplication>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QLabel>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QMainWindow>
#include <QtWidgets/QMenu>
#include <QtWidgets/QMenuBar>
#include <QtWidgets/QTextEdit>
#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QWidget>

QT_BEGIN_NAMESPACE

class Ui_MainWindow
{
public:
	QAction *actionOpen;
	QWidget *centralwidget;
	QVBoxLayout *verticalLayout_2;
	QLineEdit *lineEdit;
	QHBoxLayout *horizontalLayout;
	QLabel *label;
	QLabel *label_2;
	QHBoxLayout *horizontalLayout_2;
	QTextEdit *textEdit;
	QTextEdit *textEdit_2;
	QHBoxLayout *horizontalLayout_3;
	QLabel *label_3;
	QLabel *label_4;
	QHBoxLayout *horizontalLayout_4;
	QTextEdit *textEdit_4;
	QTextEdit *textEdit_3;
	QMenuBar *menubar;
	QMenu *menuFile;

	void setupUi(QMainWindow *MainWindow)
	{
		if (MainWindow->objectName().isEmpty())
			MainWindow->setObjectName(QString::fromUtf8("MainWindow"));
		MainWindow->resize(526, 471);
		MainWindow->setStyleSheet(QString::fromUtf8("selection-background-color: rgb(85, 85, 127);\n"
			"background-color: rgb(226, 226, 226);\n"
			""));
		actionOpen = new QAction(MainWindow);
		actionOpen->setObjectName(QString::fromUtf8("actionOpen"));
		centralwidget = new QWidget(MainWindow);
		centralwidget->setObjectName(QString::fromUtf8("centralwidget"));
		QSizePolicy sizePolicy(QSizePolicy::Maximum, QSizePolicy::Maximum);
		sizePolicy.setHorizontalStretch(0);
		sizePolicy.setVerticalStretch(0);
		sizePolicy.setHeightForWidth(centralwidget->sizePolicy().hasHeightForWidth());
		centralwidget->setSizePolicy(sizePolicy);
		centralwidget->setStyleSheet(QString::fromUtf8("background-color: rgb(170, 255, 255);"));
		verticalLayout_2 = new QVBoxLayout(centralwidget);
		verticalLayout_2->setSpacing(2);
		verticalLayout_2->setObjectName(QString::fromUtf8("verticalLayout_2"));
		verticalLayout_2->setSizeConstraint(QLayout::SetNoConstraint);
		lineEdit = new QLineEdit(centralwidget);
		lineEdit->setObjectName(QString::fromUtf8("lineEdit"));
		lineEdit->setStyleSheet(QString::fromUtf8("background-color: rgb(255, 255, 255);"));

		verticalLayout_2->addWidget(lineEdit);

		horizontalLayout = new QHBoxLayout();
		horizontalLayout->setSpacing(0);
		horizontalLayout->setObjectName(QString::fromUtf8("horizontalLayout"));
		label = new QLabel(centralwidget);
		label->setObjectName(QString::fromUtf8("label"));
		QSizePolicy sizePolicy1(QSizePolicy::Expanding, QSizePolicy::Preferred);
		sizePolicy1.setHorizontalStretch(30);
		sizePolicy1.setVerticalStretch(250);
		sizePolicy1.setHeightForWidth(label->sizePolicy().hasHeightForWidth());
		label->setSizePolicy(sizePolicy1);
		label->setStyleSheet(QString::fromUtf8("background-color: rgb(255, 230, 130);"));

		horizontalLayout->addWidget(label);

		label_2 = new QLabel(centralwidget);
		label_2->setObjectName(QString::fromUtf8("label_2"));
		QSizePolicy sizePolicy2(QSizePolicy::Expanding, QSizePolicy::Preferred);
		sizePolicy2.setHorizontalStretch(100);
		sizePolicy2.setVerticalStretch(65);
		sizePolicy2.setHeightForWidth(label_2->sizePolicy().hasHeightForWidth());
		label_2->setSizePolicy(sizePolicy2);
		label_2->setStyleSheet(QString::fromUtf8("background-color: rgb(87, 219, 255);\n"
			""));

		horizontalLayout->addWidget(label_2);


		verticalLayout_2->addLayout(horizontalLayout);

		horizontalLayout_2 = new QHBoxLayout();
		horizontalLayout_2->setSpacing(0);
		horizontalLayout_2->setObjectName(QString::fromUtf8("horizontalLayout_2"));
		textEdit = new QTextEdit(centralwidget);
		textEdit->setObjectName(QString::fromUtf8("textEdit"));
		QSizePolicy sizePolicy3(QSizePolicy::Expanding, QSizePolicy::Expanding);
		sizePolicy3.setHorizontalStretch(30);
		sizePolicy3.setVerticalStretch(250);
		sizePolicy3.setHeightForWidth(textEdit->sizePolicy().hasHeightForWidth());
		textEdit->setSizePolicy(sizePolicy3);
		textEdit->setStyleSheet(QString::fromUtf8("background-color: rgb(255, 255, 255);"));
		textEdit->setReadOnly(true);

		horizontalLayout_2->addWidget(textEdit);

		textEdit_2 = new QTextEdit(centralwidget);
		textEdit_2->setObjectName(QString::fromUtf8("textEdit_2"));
		textEdit_2->setEnabled(true);
		QSizePolicy sizePolicy4(QSizePolicy::Expanding, QSizePolicy::Expanding);
		sizePolicy4.setHorizontalStretch(100);
		sizePolicy4.setVerticalStretch(65);
		sizePolicy4.setHeightForWidth(textEdit_2->sizePolicy().hasHeightForWidth());
		textEdit_2->setSizePolicy(sizePolicy4);
		textEdit_2->setStyleSheet(QString::fromUtf8("background-color: rgb(255, 255, 255);"));
		textEdit_2->setReadOnly(true);

		horizontalLayout_2->addWidget(textEdit_2);


		verticalLayout_2->addLayout(horizontalLayout_2);

		horizontalLayout_3 = new QHBoxLayout();
		horizontalLayout_3->setSpacing(0);
		horizontalLayout_3->setObjectName(QString::fromUtf8("horizontalLayout_3"));
		label_3 = new QLabel(centralwidget);
		label_3->setObjectName(QString::fromUtf8("label_3"));
		label_3->setStyleSheet(QString::fromUtf8("background-color: rgb(255, 230, 130);"));

		horizontalLayout_3->addWidget(label_3);

		label_4 = new QLabel(centralwidget);
		label_4->setObjectName(QString::fromUtf8("label_4"));
		label_4->setStyleSheet(QString::fromUtf8("background-color: rgb(87, 219, 255);\n"
			""));

		horizontalLayout_3->addWidget(label_4);


		verticalLayout_2->addLayout(horizontalLayout_3);

		horizontalLayout_4 = new QHBoxLayout();
		horizontalLayout_4->setSpacing(0);
		horizontalLayout_4->setObjectName(QString::fromUtf8("horizontalLayout_4"));
		textEdit_4 = new QTextEdit(centralwidget);
		textEdit_4->setObjectName(QString::fromUtf8("textEdit_4"));
		QSizePolicy sizePolicy5(QSizePolicy::Expanding, QSizePolicy::Expanding);
		sizePolicy5.setHorizontalStretch(0);
		sizePolicy5.setVerticalStretch(65);
		sizePolicy5.setHeightForWidth(textEdit_4->sizePolicy().hasHeightForWidth());
		textEdit_4->setSizePolicy(sizePolicy5);
		textEdit_4->setStyleSheet(QString::fromUtf8("background-color: rgb(255, 255, 255);"));
		textEdit_4->setReadOnly(true);

		horizontalLayout_4->addWidget(textEdit_4);

		textEdit_3 = new QTextEdit(centralwidget);
		textEdit_3->setObjectName(QString::fromUtf8("textEdit_3"));
		QSizePolicy sizePolicy6(QSizePolicy::Expanding, QSizePolicy::Expanding);
		sizePolicy6.setHorizontalStretch(0);
		sizePolicy6.setVerticalStretch(35);
		sizePolicy6.setHeightForWidth(textEdit_3->sizePolicy().hasHeightForWidth());
		textEdit_3->setSizePolicy(sizePolicy6);
		textEdit_3->setStyleSheet(QString::fromUtf8("background-color: rgb(255, 255, 255);"));
		textEdit_3->setReadOnly(true);

		horizontalLayout_4->addWidget(textEdit_3);


		verticalLayout_2->addLayout(horizontalLayout_4);

		MainWindow->setCentralWidget(centralwidget);
		menubar = new QMenuBar(MainWindow);
		menubar->setObjectName(QString::fromUtf8("menubar"));
		menubar->setGeometry(QRect(0, 0, 526, 17));
		menuFile = new QMenu(menubar);
		menuFile->setObjectName(QString::fromUtf8("menuFile"));
		MainWindow->setMenuBar(menubar);

		menubar->addAction(menuFile->menuAction());
		menuFile->addAction(actionOpen);

		retranslateUi(MainWindow);

		QMetaObject::connectSlotsByName(MainWindow);
	} // setupUi

	void retranslateUi(QMainWindow *MainWindow)
	{
		MainWindow->setWindowTitle(QApplication::translate("MainWindow", "MainWindow", nullptr));
		actionOpen->setText(QApplication::translate("MainWindow", "Open", nullptr));
#ifndef QT_NO_WHATSTHIS
		lineEdit->setWhatsThis(QApplication::translate("MainWindow", "<html><head/><body><p>enter command</p><p><br/></p></body></html>", nullptr));
#endif // QT_NO_WHATSTHIS
		lineEdit->setText(QString());
		label->setText(QApplication::translate("MainWindow", " Connected devices:", nullptr));
		label_2->setText(QApplication::translate("MainWindow", "Full information about captured packets", nullptr));
		label_3->setText(QApplication::translate("MainWindow", "  Captured packets in hex", nullptr));
		label_4->setText(QApplication::translate("MainWindow", "  Captured packets in ASCII", nullptr));
		menuFile->setTitle(QApplication::translate("MainWindow", "File", nullptr));
	} // retranslateUi

};

namespace Ui {
	class MainWindow : public Ui_MainWindow {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_MAINWINDOW_H
