#include <windows.h>
#include <iostream>
#include <string>
#include <thread>
#include <atomic>
#include <unordered_map>
#include <tlhelp32.h>
#include <shellapi.h>
#include <tchar.h>
#include <psapi.h>
#include <shlwapi.h>
#include <vector>
#include <fstream>
#include <ctime>
#include <sstream>
#include <mutex>
#include <winternl.h>
#pragma comment(lib, "shlwapi.lib")

//提权
void EnsureRunAsAdministrator() {
    // 检查当前程序是否以管理员身份运行
    BOOL isElevated = FALSE;
    HANDLE hToken = NULL;
    TOKEN_ELEVATION elevation;
    DWORD dwSize;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &dwSize)) {
            isElevated = elevation.TokenIsElevated;
        }
        CloseHandle(hToken);
    }

    if (!isElevated) {
        // 获取当前程序的路径
        char path[MAX_PATH];
        GetModuleFileNameA(NULL, path, MAX_PATH);

        // 使用ShellExecute以管理员身份运行当前程序
        ShellExecuteA(NULL, "runas", path, NULL, NULL, SW_NORMAL);

        // 退出当前程序
        std::cout << "Please approve the UAC prompt to run as administrator." << std::endl;
        exit(0); // 退出当前程序
    }

    // 如果已经以管理员身份运行，不执行任何操作
}

// ==== 日志模块 ====
class Logger {
private:
    std::ofstream logFile;
    std::mutex logMutex;
    std::atomic<bool> isClosing{ false };
    const std::string logPath = "jiyuunlock.log";

    // 禁止复制和赋值
    Logger() = default;
    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;

    // 内部字符串编码转换函数
    static std::string WideCharToMultiByteString(const std::wstring& wideStr) {
        if (wideStr.empty()) return "";
        int sizeNeeded = WideCharToMultiByte(CP_UTF8, 0, wideStr.c_str(), (int)wideStr.size(), NULL, 0, NULL, NULL);
        if (sizeNeeded <= 0) return "";
        std::string narrowStr(sizeNeeded, 0);
        WideCharToMultiByte(CP_UTF8, 0, wideStr.c_str(), (int)wideStr.size(), &narrowStr[0], sizeNeeded, NULL, NULL);
        return narrowStr;
    }

    static std::wstring MultiByteToWideCharString(const std::string& narrowStr) {
        if (narrowStr.empty()) return L"";
        int sizeNeeded = MultiByteToWideChar(CP_UTF8, 0, narrowStr.c_str(), (int)narrowStr.size(), NULL, 0);
        if (sizeNeeded <= 0) return L"";
        std::wstring wideStr(sizeNeeded, 0);
        MultiByteToWideChar(CP_UTF8, 0, narrowStr.c_str(), (int)narrowStr.size(), &wideStr[0], sizeNeeded);
        return wideStr;
    }

public:
    // 单例模式访问
    static Logger& GetInstance() {
        static Logger instance;
        return instance;
    }

    ~Logger() {
        isClosing = true; // 设置关闭标志
        std::lock_guard<std::mutex> lock(logMutex);
        if (logFile.is_open()) {
            logFile << "[" << GetCurrentTime() << "] [INFO] Logger shutting down." << std::endl;
            logFile.close();
        }
    }

    // 获取当前时间（线程安全）
    std::string GetCurrentTime() {
        time_t now = time(0);
        struct tm tstruct;
        char buf[80];
        localtime_s(&tstruct, &now);
        strftime(buf, sizeof(buf), "%Y-%m-%d %X", &tstruct);
        return buf;
    }

    // 日志记录（支持宽字符串）
    void Log(const std::string& level, const std::string& message) {
        if (isClosing) return; // 避免析构后写入
        std::lock_guard<std::mutex> lock(logMutex);

        // 延迟初始化文件流
        if (!logFile.is_open()) {
            logFile.open(logPath, std::ios::app | std::ios::binary);
            if (!logFile) {
                std::cerr << "无法打开日志文件: " << logPath << std::endl;
                return;
            }
            logFile << "[" << GetCurrentTime() << "] [INFO] Logger initialized." << std::endl;
        }

        logFile << "[" << GetCurrentTime() << "] [" << level << "] " << message << std::endl;
        logFile.flush(); // 确保日志及时写入
    }

    void Log(const std::string& level, const std::wstring& message) {
        Log(level, WideCharToMultiByteString(message));
    }
};
// 全局访问点
Logger& logger = Logger::GetInstance();

// ==== 配置模块 ====
class ConfigManager {
private:
    const std::string configPath = "jiyuunlock.cfg";
    std::unordered_map<std::string, std::string> configData;

    void ParseLine(const std::string& line) {
        size_t pos = line.find('=');
        if (pos != std::string::npos) {
            std::string key = line.substr(0, pos);
            std::string value = line.substr(pos + 1);
            configData[key] = value;
        }
    }

public:
    ConfigManager() {
        std::ifstream file(configPath);
        std::string line;
        while (std::getline(file, line)) {
            ParseLine(line);
        }
    }

    void SaveConfig() {
        std::ofstream file(configPath);
        for (const auto& pair : configData) {
            file << pair.first << "=" << pair.second << std::endl;
        }
    }

    std::string Get(const std::string& key, const std::string& defaultValue = "") {
        auto it = configData.find(key);
        return (it != configData.end()) ? it->second : defaultValue;
    }

    void Set(const std::string& key, const std::string& value) {
        configData[key] = value;
        SaveConfig();
    }
};
ConfigManager config;

std::wstring DetectMythwarePath() {
    logger.Log("INFO", "正在检测Mythware安装路径...");
    // 1. 检查注册表
    HKEY hKey;
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Mythware", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        WCHAR installPath[MAX_PATH];
        DWORD bufSize = MAX_PATH * sizeof(WCHAR);
        if (RegQueryValueEx(hKey, L"InstallPath", NULL, NULL, (LPBYTE)installPath, &bufSize) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return installPath;
        }
        RegCloseKey(hKey);
    }

    // 2. 检查常见安装路径
    const std::vector<std::wstring> commonPaths = {
        L"C:\\Program Files (x86)\\Mythware",
        L"C:\\Program Files\\Mythware",
        L"D:\\Program Files (x86)\\Mythware",
        L"D:\\Program Files\\Mythware"
    };

    for (const auto& path : commonPaths) {
        if (PathFileExists(path.c_str())) {
            return path;
        }
    }
    logger.Log("INFO", "未找到Mythware安装路径");
    return L""; // 未找到
}

// 辅助函数：将宽字符字符串转换为普通字符字符串
std::string WideCharToMultiByteString(const std::wstring& wideStr) {
    int sizeNeeded = WideCharToMultiByte(CP_UTF8, 0, &wideStr[0], (int)wideStr.size(), NULL, 0, NULL, NULL);
    std::string strTo(sizeNeeded, 0);
    WideCharToMultiByte(CP_UTF8, 0, &wideStr[0], (int)wideStr.size(), &strTo[0], sizeNeeded, NULL, NULL);
    return strTo;
}

std::wstring MultiByteToWideCharString(const std::string& narrowStr) {
    int sizeNeeded = MultiByteToWideChar(CP_UTF8, 0, narrowStr.c_str(), (int)narrowStr.size(), NULL, 0);
    std::wstring wideStr(sizeNeeded, 0);
    MultiByteToWideChar(CP_UTF8, 0, narrowStr.c_str(), (int)narrowStr.size(), &wideStr[0], sizeNeeded);
    return wideStr;
}

std::atomic<bool> topRunning(false);
std::thread topThread;

void topWindow(const std::atomic<bool>& running, HWND hwnd, int interval) {
    while (running) {
        SetWindowPos(hwnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
        Sleep(interval); // 每interval毫秒置顶一次
    }
    // 退出循环后取消置顶
    SetWindowPos(hwnd, HWND_NOTOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
}

// 定义函数指针类型
typedef NTSTATUS(NTAPI* pNtSuspendProcess)(HANDLE ProcessHandle);
typedef NTSTATUS(NTAPI* pNtResumeProcess)(HANDLE ProcessHandle);

// 挂起整个进程
bool SuspendProcess(DWORD pid) {
    Logger::GetInstance().Log("INFO", "正在挂起进程...");
    // 获取目标进程句柄
    HANDLE hProcess = OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, pid);
    if (hProcess == NULL) {
        std::cerr << "OpenProcess failed. Error: " << GetLastError() << std::endl;
        return false;
    }

    // 从 ntdll.dll 获取 NtSuspendProcess 函数
    pNtSuspendProcess NtSuspendProcess = (pNtSuspendProcess)GetProcAddress(
        GetModuleHandleW(L"ntdll.dll"), "NtSuspendProcess");

    if (NtSuspendProcess == NULL) {
        std::cerr << "GetProcAddress failed for NtSuspendProcess" << std::endl;
        CloseHandle(hProcess);
        return false;
    }

    // 调用函数挂起进程
    NTSTATUS status = NtSuspendProcess(hProcess);
    CloseHandle(hProcess);

    if (status != 0) { // 0 表示成功
        std::cerr << "NtSuspendProcess failed with status: 0x" << std::hex << status << std::endl;
        return false;
    }
    return true;
}

// 恢复整个进程
bool ResumeProcess(DWORD pid) {
    Logger::GetInstance().Log("INFO", "正在恢复进程...");
    HANDLE hProcess = OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, pid);
    if (hProcess == NULL) {
        std::cerr << "OpenProcess failed. Error: " << GetLastError() << std::endl;
        return false;
    }

    pNtResumeProcess NtResumeProcess = (pNtResumeProcess)GetProcAddress(
        GetModuleHandleW(L"ntdll.dll"), "NtResumeProcess");

    if (NtResumeProcess == NULL) {
        std::cerr << "GetProcAddress failed for NtResumeProcess" << std::endl;
        CloseHandle(hProcess);
        return false;
    }

    NTSTATUS status = NtResumeProcess(hProcess);
    CloseHandle(hProcess);

    if (status != 0) {
        std::cerr << "NtResumeProcess failed with status: 0x" << std::hex << status << std::endl;
        return false;
    }
    return true;
}

BOOL unloadHook(DWORD pid) {
     std::cout << "正在卸载..." << std::endl;
     if (!SuspendProcess(pid)) {
         Logger::GetInstance().Log("ERROR", "挂起进程失败");
     }
     else {
         Logger::GetInstance().Log("INFO", "挂起进程成功");
     }
     Sleep(500);// 等待500毫秒
     if (!ResumeProcess(pid)) {
         Logger::GetInstance().Log("ERROR", "恢复进程失败");
         return FALSE;
     }
     else {
         std::cout << "卸载完成" << std::endl;
         Logger::GetInstance().Log("INFO", "恢复进程成功");
         return TRUE;
     }
}

BOOL GetProcessIdFromFileName(const TCHAR* filePath, DWORD& processId) {
    PROCESSENTRY32 entry = { sizeof(PROCESSENTRY32) };
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (snapshot == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    if (Process32First(snapshot, &entry)) {
        do {
            TCHAR processPath[MAX_PATH];
            HANDLE processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, entry.th32ProcessID);
            if (processHandle != NULL) {
                if (GetModuleFileNameEx(processHandle, NULL, processPath, MAX_PATH)) {
                    if (_tcsicmp(filePath, processPath) == 0) {
                        processId = entry.th32ProcessID;
                        CloseHandle(processHandle);
                        CloseHandle(snapshot);
                        return TRUE;
                    }
                }
                CloseHandle(processHandle);
            }
        } while (Process32Next(snapshot, &entry));
    }
    CloseHandle(snapshot);
    return FALSE;
}

// 尝试结束进程
BOOL TryToTerminateProcess(DWORD processId) {
    HANDLE processHandle = OpenProcess(PROCESS_TERMINATE, FALSE, processId);
    if (processHandle != NULL) {
        BOOL result = TerminateProcess(processHandle, 0);
        CloseHandle(processHandle);
        return result;
    }
    return FALSE;
}

// 删除文件，如果文件被占用则尝试结束占用进程
BOOL DeleteFileWithProcessCheck(const TCHAR* filePath) {
    DWORD processId = 0;
    if (GetProcessIdFromFileName(filePath, processId)) {
        std::wcout << L"文件被进程占用，尝试结束进程ID: " << processId << std::endl;
        if (TryToTerminateProcess(processId)) {
            std::wcout << L"进程已结束，尝试删除文件..." << std::endl;
        }
        else {
            std::wcerr << L"无法结束进程，无法删除文件。" << std::endl;
            return FALSE;
        }
    }

    if (DeleteFile(filePath)) {
        std::wcout << L"文件删除成功: " << filePath << std::endl;
        logger.Log("INFO", "成功删除文件");
        return TRUE;
    }
    else {
        logger.Log("INFO", "删除文件失败");
        return FALSE;
    }
}

// 删除指定目录下的所有文件
void DeleteAllFilesInDirectory(const TCHAR* directoryPath) {
    TCHAR searchPath[MAX_PATH];
    _stprintf_s(searchPath, MAX_PATH, _T("%s\\*.*"), directoryPath);

    WIN32_FIND_DATA findFileData;
    HANDLE hFind = FindFirstFile(searchPath, &findFileData);

    if (hFind == INVALID_HANDLE_VALUE) {
        std::wcerr << L"无法打开目录: " << directoryPath << std::endl;
        return;
    }

    do {
        if (findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (_tcsicmp(findFileData.cFileName, _T(".")) != 0 && _tcsicmp(findFileData.cFileName, _T("..")) != 0) {
                TCHAR subDirPath[MAX_PATH];
                _stprintf_s(subDirPath, MAX_PATH, _T("%s\\%s"), directoryPath, findFileData.cFileName);
                DeleteAllFilesInDirectory(subDirPath); // 递归删除子目录中的文件
            }
        }
        else {
            TCHAR filePath[MAX_PATH];
            _stprintf_s(filePath, MAX_PATH, _T("%s\\%s"), directoryPath, findFileData.cFileName);
            DeleteFileWithProcessCheck(filePath); // 删除文件
            std::cout << "删除文件: " << filePath << std::endl;
        }
    } while (FindNextFile(hFind, &findFileData) != 0);

    FindClose(hFind);
}

bool taskkill(DWORD processID) {
    // 打开目标进程，获取句柄
    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, processID);
    if (hProcess == NULL) {
        std::cerr << "Failed to open process. Error: " << GetLastError() << std::endl;
        return false; // 打开进程失败
    }

    // 尝试终止进程
    if (!TerminateProcess(hProcess, 0)) {
        std::cerr << "Failed to terminate process. Error: " << GetLastError() << std::endl;
        CloseHandle(hProcess); // 关闭句柄
        return false; // 终止进程失败
    }

    // 关闭句柄
    CloseHandle(hProcess);
    return true; // 成功终止进程
    logger.Log("INFO", "成功终止进程"+std::to_string(processID));
}

// 检测窗口是否置顶
bool IsWindowTopMost(HWND hwnd) {
    if (!IsWindow(hwnd)) return false;
    LONG_PTR exStyle = GetWindowLongPtr(hwnd, GWL_EXSTYLE);
    return (exStyle & WS_EX_TOPMOST) != 0;
}

// 检测窗口是否全屏
bool IsWindowFullScreen(HWND hwnd) {
    if (!IsWindow(hwnd)) return false;
    RECT windowRect, monitorRect;
    GetWindowRect(hwnd, &windowRect);
    MONITORINFO mi = { sizeof(mi) };
    GetMonitorInfo(MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST), &mi);
    monitorRect = mi.rcMonitor;

    return (windowRect.left == monitorRect.left && windowRect.top == monitorRect.top &&
        windowRect.right == monitorRect.right && windowRect.bottom == monitorRect.bottom);
}

// 最小化窗口
void MinimizeWindow(HWND hwnd) {
    if (hwnd != nullptr && IsWindow(hwnd)) {
        if (!ShowWindow(hwnd, SW_MINIMIZE)) {
            std::cerr << "无法最小化窗口。错误码：" << GetLastError() << "\n";
            logger.Log("ERROR", "无法最小化窗口。错误码：" + std::to_string(GetLastError()));
        }
    }
}

// 枚举窗口回调函数
BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam) {
    DWORD targetProcessId = static_cast<DWORD>(lParam);
    DWORD processId;
    GetWindowThreadProcessId(hwnd, &processId);

    if (processId != targetProcessId) {
        return TRUE; // 不是目标程序的窗口，继续枚举
    }

    if (IsWindowVisible(hwnd) && (IsWindowTopMost(hwnd) || IsWindowFullScreen(hwnd))) {
        MinimizeWindow(hwnd);
        wchar_t windowName[256];
        GetWindowTextW(hwnd, windowName, sizeof(windowName) / sizeof(wchar_t));
        std::wcout << L"已最小化一个符合条件的窗口：" << windowName << "\n";
        logger.Log("INFO", "已最小化一个符合条件的窗口：" + WideCharToMultiByteString(windowName));
    }

    return TRUE; // 继续枚举
}

// 检测窗口的线程函数
void DetectWindows(const std::atomic<bool>& running, DWORD targetProcessId, HWND hwnd) {
    while (running) {
        EnumWindows(EnumWindowsProc, static_cast<LPARAM>(targetProcessId));
        Sleep(200); // 每200毫秒检测一次
    }
}

// 获取目标程序的进程ID
DWORD GetProcessIdByName(const std::string& processName) {
    DWORD processId = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 processEntry = { sizeof(PROCESSENTRY32) };
        if (Process32First(hSnapshot, &processEntry)) {
            do {
                std::wstring wideProcessName(processEntry.szExeFile);
                std::string convertedProcessName = WideCharToMultiByteString(wideProcessName);
                if (convertedProcessName == processName) {
                    processId = processEntry.th32ProcessID;
                    break;
                }
            } while (Process32Next(hSnapshot, &processEntry));
        }
        CloseHandle(hSnapshot);
    }
    CloseHandle(hSnapshot);
    return processId;
}

int main() {
    logger.Log("INFO", "\n========+========\n程序启动");
    EnsureRunAsAdministrator();
    HWND hwnd = GetForegroundWindow();

    // 初始化配置
    ConfigManager config;

    // 获取或检测配置
    std::string processName = config.Get("process_name", "StudentMain.exe");
    logger.Log("INFO", "获取或检测配置");
    std::wstring mythwarePath = MultiByteToWideCharString(config.Get("mythware_path", ""));  //极域路径

    // 如果路径未配置，尝试自动检测
    if (mythwarePath.empty()) {
        mythwarePath = DetectMythwarePath();
        if (!mythwarePath.empty()) {
            config.Set("mythware_path", WideCharToMultiByteString(mythwarePath));
        }
    }

    // 设置窗口置顶
    SetWindowPos(hwnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);

    // 自动启动检测
    std::atomic<bool> running(config.Get("auto_start", "false") == "true");
    std::thread detectThread;

    if (running) {
        DWORD pid = GetProcessIdByName(processName);
        if (pid != 0) {
            detectThread = std::thread(DetectWindows, std::ref(running), pid, hwnd);
            logger.Log("INFO", "自动启动窗口监控" + std::to_string(pid));
        }
        else {
            running = false;
            config.Set("auto_start", "false");
            logger.Log("WARNING", "自动启动失败：未找到进程");
        }
    }

TiaoZhuan:
    std::cout << "版本号：2.6.5";
    std::cout << "欢迎使用jiyuunlock\n";
    std::cout << "详情命令请输入help 或查阅手册\n\n";

    DWORD targetProcessId = GetProcessIdByName(processName);// 获取进程ID
    if (targetProcessId == 0) {
        std::cout << "警告：未检测到极域未运行\n";
        logger.Log("WARNING", "未检测到目标进程" + std::to_string(targetProcessId));
        std::cout << "可重设极域主进程名\n";
        std::cout << "请输入进程名：";
        std::cin >> processName;
        goto TiaoZhuan;
    }

    std::cout << "检测到极域的进程ID为：" << targetProcessId << "\n";
    logger.Log("INFO", "检测到进程ID: " + std::to_string(targetProcessId));

    std::cout << "请输入命令: ";

    while (true) {
        SetWindowPos(hwnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
        std::string command;
        std::cin >> command;

        if (command == "windowsopen") {
            DWORD targetProcessId = GetProcessIdByName(processName);// 获取进程ID
            if (!running) {
                running = true;
                config.Set("auto_start", "true");
                if (detectThread.joinable()) detectThread.join(); // 确保线程安全
                detectThread = std::thread(DetectWindows, std::ref(running), targetProcessId, hwnd);
                std::cout << "窗口监控已开启\n";
                logger.Log("INFO", "窗口监控已开启");
            }
            else {
                std::cout << "监控已在运行中\n";
                logger.Log("WARNING", "重复开启请求");
            }
        }
        else if (command == "windowsclose") {
            DWORD targetProcessId = GetProcessIdByName(processName);
            if (running) {
                running = false;
                config.Set("auto_start", "false");
                if (detectThread.joinable()) {
                    detectThread.join();
                    std::cout << "窗口监控已关闭\n";
                    logger.Log("INFO", "窗口监控已关闭");
                }
            }
            else {
                std::cout << "监控未运行\n";
                logger.Log("WARNING", "尝试关闭未运行的监控");
            }
        }
        else if (command == "exit") {
            DWORD targetProcessId = GetProcessIdByName(processName);
            if (running) {
                running = false;
                config.Set("auto_start", "false");
                if (detectThread.joinable()) detectThread.join();
            }
            std::cout << "退出程序\n";
            logger.Log("INFO", "用户退出程序");
            break;
        }
        else if (command == "kill") {
            DWORD targetProcessId = GetProcessIdByName(processName);
            if (taskkill(targetProcessId)) {
                std::cout << "进程终止成功\n";
                logger.Log("INFO", "成功终止进程"+std::to_string(targetProcessId));
                goto TiaoZhuan; // 重新检测进程状态
            }
            else {
                std::cout << "终止失败\n";
                logger.Log("ERROR", "终止进程失败"+std::to_string(GetLastError()));
            }
        }
        else if (command == "del") {
            DWORD targetProcessId = GetProcessIdByName(processName);
            const TCHAR* directoryPath = _T("C:\\Program Files (x86)\\Mythware");
            DeleteAllFilesInDirectory(directoryPath);
            logger.Log("WARNING", "执行删除操作: " + WideCharToMultiByteString(directoryPath));
        }
        else if (command == "top") {
            std::string subcmd;
            std::cin >> subcmd;
            if (subcmd == "s") {
                int time = 0;
                std::cout << "请输入置顶循环间隔时间（毫秒,默认为0，消耗资源大）: ";
                std::cin >> time;
                if (!topRunning) {
                    topRunning = true;
                    if (topThread.joinable()) topThread.join();
                    topThread = std::thread(topWindow, std::ref(topRunning), hwnd, time);
                    std::cout << "窗口持续置顶已开启\n";
                    logger.Log("INFO", "窗口持续置顶开启");
                }
                else {
                    std::cout << "置顶功能已在运行中\n";
                    logger.Log("WARNING", "重复开启置顶请求");
                }
            }
            else if (subcmd == "c") {
                if (topRunning) {
                    topRunning = false;
                    if (topThread.joinable()) {
                        topThread.join();
                        std::cout << "窗口持续置顶已关闭\n";
                        logger.Log("INFO", "窗口持续置顶关闭");
                    }
                }
                else {
                    std::cout << "置顶功能未运行\n";
                    logger.Log("WARNING", "尝试关闭未运行的置顶功能");
                }
            }
            else {
                std::cout << "无效的top命令，使用top s或top c\n";
                logger.Log("WARNING", "无效的top子命令: " + subcmd);
            }
        }
        else if (command == "putRod") {
            std::string path;
            std::cout << "请输入极域路径: ";
            std::cin >> path;
            config.Set("path", path);
            std::cout << "极域路径已设置\n";
            logger.Log("INFO", "设置极域路径: " + path);
        }
        else if (command == "putName") {
            std::string name;
            std::cout << "请输入极域主程序名: ";
            std::cin >> name;
            config.Set("name", name);
            std::cout << "极域主程序名已设置\n";
            DetectMythwarePath();
            logger.Log("INFO", "设置极域主程序名: " + name);
        }
        else if (command == "unloadhook") {
            DWORD targetProcessId = GetProcessIdByName(processName);
            if (unloadHook(targetProcessId)) {
                std::cout << "卸载钩子成功\n";
            }
            else {
                std::cerr << "卸载钩子失败\n";
            }
        }
        else if (command == "help") {
            DWORD targetProcessId = GetProcessIdByName(processName);
            std::cout << "命令列表:\n"
                << "  windowsopen  - 开启窗口监控(让老师的屏幕广播和黑屏失效)\n"
                << "  windowsclose - 关闭窗口监控\n"
                << "  top s        - 开启持续置顶(即使黑屏安静此程序依旧能显示)\n"
                << "  top c        - 关闭持续置顶\n"
                << "  kill         - 终止极域进程(关闭程序,容易让老师发现)\n"
                << "  del          - 删除极域文件\n"
                << "  exit         - 退出程序(退出此程序)\n"
                << "  putRod       - 设置极域路径,默认为C:\\Program Files (x86)\\Mythware\n"
                << "  putName      - 设置极域主程序名,默认为StudentMain.exe\n"
                << "  unloadhook   - 卸载钩子(如果发现无法输入文字执行此指令)\n";
            logger.Log("INFO", "查看帮助信息");
        }
        else {
            std::cout << "无效命令，输入help查看帮助\n";
            logger.Log("WARNING", "无效命令: " + command);
        }
    }

    logger.Log("INFO", "程序正常退出");
    return 0;
}