#include <QCoreApplication> // Qt 的非 GUI 应用程序核心类
#include <QDebug>           // 用于调试输出
#include "Inc/chat_server.h" // 包含 ChatServer 类

int main(int argc, char *argv[]) {
    QCoreApplication a(argc, argv); // 初始化 Qt 应用程序事件循环

    ChatServer server; // 创建 ChatServer 实例

    int port = 12345; // 定义服务器监听的端口
    if (server.startServer(port)) {
    } else {
        qCritical() << "未能启动聊天服务器，端口为" << port << "。程序将退出。";
        return 1; // 服务器启动失败，程序退出
    }

    return a.exec(); // 启动 Qt 事件循环，服务器开始处理事件
}