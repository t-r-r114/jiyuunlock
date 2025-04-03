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

//��Ȩ
void EnsureRunAsAdministrator() {
    // ��鵱ǰ�����Ƿ��Թ���Ա�������
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
        // ��ȡ��ǰ�����·��
        char path[MAX_PATH];
        GetModuleFileNameA(NULL, path, MAX_PATH);

        // ʹ��ShellExecute�Թ���Ա������е�ǰ����
        ShellExecuteA(NULL, "runas", path, NULL, NULL, SW_NORMAL);

        // �˳���ǰ����
        std::cout << "Please approve the UAC prompt to run as administrator." << std::endl;
        exit(0); // �˳���ǰ����
    }

    // ����Ѿ��Թ���Ա������У���ִ���κβ���
}

// ==== ��־ģ�� ====
class Logger {
private:
    std::ofstream logFile;
    std::mutex logMutex;
    std::atomic<bool> isClosing{ false };
    const std::string logPath = "jiyuunlock.log";

    // ��ֹ���ƺ͸�ֵ
    Logger() = default;
    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;

    // �ڲ��ַ�������ת������
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
    // ����ģʽ����
    static Logger& GetInstance() {
        static Logger instance;
        return instance;
    }

    ~Logger() {
        isClosing = true; // ���ùرձ�־
        std::lock_guard<std::mutex> lock(logMutex);
        if (logFile.is_open()) {
            logFile << "[" << GetCurrentTime() << "] [INFO] Logger shutting down." << std::endl;
            logFile.close();
        }
    }

    // ��ȡ��ǰʱ�䣨�̰߳�ȫ��
    std::string GetCurrentTime() {
        time_t now = time(0);
        struct tm tstruct;
        char buf[80];
        localtime_s(&tstruct, &now);
        strftime(buf, sizeof(buf), "%Y-%m-%d %X", &tstruct);
        return buf;
    }

    // ��־��¼��֧�ֿ��ַ�����
    void Log(const std::string& level, const std::string& message) {
        if (isClosing) return; // ����������д��
        std::lock_guard<std::mutex> lock(logMutex);

        // �ӳٳ�ʼ���ļ���
        if (!logFile.is_open()) {
            logFile.open(logPath, std::ios::app | std::ios::binary);
            if (!logFile) {
                std::cerr << "�޷�����־�ļ�: " << logPath << std::endl;
                return;
            }
            logFile << "[" << GetCurrentTime() << "] [INFO] Logger initialized." << std::endl;
        }

        logFile << "[" << GetCurrentTime() << "] [" << level << "] " << message << std::endl;
        logFile.flush(); // ȷ����־��ʱд��
    }

    void Log(const std::string& level, const std::wstring& message) {
        Log(level, WideCharToMultiByteString(message));
    }
};
// ȫ�ַ��ʵ�
Logger& logger = Logger::GetInstance();

// ==== ����ģ�� ====
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
    logger.Log("INFO", "���ڼ��Mythware��װ·��...");
    // 1. ���ע���
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

    // 2. ��鳣����װ·��
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
    logger.Log("INFO", "δ�ҵ�Mythware��װ·��");
    return L""; // δ�ҵ�
}

// ���������������ַ��ַ���ת��Ϊ��ͨ�ַ��ַ���
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
        Sleep(interval); // ÿinterval�����ö�һ��
    }
    // �˳�ѭ����ȡ���ö�
    SetWindowPos(hwnd, HWND_NOTOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
}

// ���庯��ָ������
typedef NTSTATUS(NTAPI* pNtSuspendProcess)(HANDLE ProcessHandle);
typedef NTSTATUS(NTAPI* pNtResumeProcess)(HANDLE ProcessHandle);

// ������������
bool SuspendProcess(DWORD pid) {
    Logger::GetInstance().Log("INFO", "���ڹ������...");
    // ��ȡĿ����̾��
    HANDLE hProcess = OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, pid);
    if (hProcess == NULL) {
        std::cerr << "OpenProcess failed. Error: " << GetLastError() << std::endl;
        return false;
    }

    // �� ntdll.dll ��ȡ NtSuspendProcess ����
    pNtSuspendProcess NtSuspendProcess = (pNtSuspendProcess)GetProcAddress(
        GetModuleHandleW(L"ntdll.dll"), "NtSuspendProcess");

    if (NtSuspendProcess == NULL) {
        std::cerr << "GetProcAddress failed for NtSuspendProcess" << std::endl;
        CloseHandle(hProcess);
        return false;
    }

    // ���ú����������
    NTSTATUS status = NtSuspendProcess(hProcess);
    CloseHandle(hProcess);

    if (status != 0) { // 0 ��ʾ�ɹ�
        std::cerr << "NtSuspendProcess failed with status: 0x" << std::hex << status << std::endl;
        return false;
    }
    return true;
}

// �ָ���������
bool ResumeProcess(DWORD pid) {
    Logger::GetInstance().Log("INFO", "���ڻָ�����...");
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
     std::cout << "����ж��..." << std::endl;
     if (!SuspendProcess(pid)) {
         Logger::GetInstance().Log("ERROR", "�������ʧ��");
     }
     else {
         Logger::GetInstance().Log("INFO", "������̳ɹ�");
     }
     Sleep(500);// �ȴ�500����
     if (!ResumeProcess(pid)) {
         Logger::GetInstance().Log("ERROR", "�ָ�����ʧ��");
         return FALSE;
     }
     else {
         std::cout << "ж�����" << std::endl;
         Logger::GetInstance().Log("INFO", "�ָ����̳ɹ�");
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

// ���Խ�������
BOOL TryToTerminateProcess(DWORD processId) {
    HANDLE processHandle = OpenProcess(PROCESS_TERMINATE, FALSE, processId);
    if (processHandle != NULL) {
        BOOL result = TerminateProcess(processHandle, 0);
        CloseHandle(processHandle);
        return result;
    }
    return FALSE;
}

// ɾ���ļ�������ļ���ռ�����Խ���ռ�ý���
BOOL DeleteFileWithProcessCheck(const TCHAR* filePath) {
    DWORD processId = 0;
    if (GetProcessIdFromFileName(filePath, processId)) {
        std::wcout << L"�ļ�������ռ�ã����Խ�������ID: " << processId << std::endl;
        if (TryToTerminateProcess(processId)) {
            std::wcout << L"�����ѽ���������ɾ���ļ�..." << std::endl;
        }
        else {
            std::wcerr << L"�޷��������̣��޷�ɾ���ļ���" << std::endl;
            return FALSE;
        }
    }

    if (DeleteFile(filePath)) {
        std::wcout << L"�ļ�ɾ���ɹ�: " << filePath << std::endl;
        logger.Log("INFO", "�ɹ�ɾ���ļ�");
        return TRUE;
    }
    else {
        logger.Log("INFO", "ɾ���ļ�ʧ��");
        return FALSE;
    }
}

// ɾ��ָ��Ŀ¼�µ������ļ�
void DeleteAllFilesInDirectory(const TCHAR* directoryPath) {
    TCHAR searchPath[MAX_PATH];
    _stprintf_s(searchPath, MAX_PATH, _T("%s\\*.*"), directoryPath);

    WIN32_FIND_DATA findFileData;
    HANDLE hFind = FindFirstFile(searchPath, &findFileData);

    if (hFind == INVALID_HANDLE_VALUE) {
        std::wcerr << L"�޷���Ŀ¼: " << directoryPath << std::endl;
        return;
    }

    do {
        if (findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (_tcsicmp(findFileData.cFileName, _T(".")) != 0 && _tcsicmp(findFileData.cFileName, _T("..")) != 0) {
                TCHAR subDirPath[MAX_PATH];
                _stprintf_s(subDirPath, MAX_PATH, _T("%s\\%s"), directoryPath, findFileData.cFileName);
                DeleteAllFilesInDirectory(subDirPath); // �ݹ�ɾ����Ŀ¼�е��ļ�
            }
        }
        else {
            TCHAR filePath[MAX_PATH];
            _stprintf_s(filePath, MAX_PATH, _T("%s\\%s"), directoryPath, findFileData.cFileName);
            DeleteFileWithProcessCheck(filePath); // ɾ���ļ�
            std::cout << "ɾ���ļ�: " << filePath << std::endl;
        }
    } while (FindNextFile(hFind, &findFileData) != 0);

    FindClose(hFind);
}

bool taskkill(DWORD processID) {
    // ��Ŀ����̣���ȡ���
    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, processID);
    if (hProcess == NULL) {
        std::cerr << "Failed to open process. Error: " << GetLastError() << std::endl;
        return false; // �򿪽���ʧ��
    }

    // ������ֹ����
    if (!TerminateProcess(hProcess, 0)) {
        std::cerr << "Failed to terminate process. Error: " << GetLastError() << std::endl;
        CloseHandle(hProcess); // �رվ��
        return false; // ��ֹ����ʧ��
    }

    // �رվ��
    CloseHandle(hProcess);
    return true; // �ɹ���ֹ����
    logger.Log("INFO", "�ɹ���ֹ����"+std::to_string(processID));
}

// ��ⴰ���Ƿ��ö�
bool IsWindowTopMost(HWND hwnd) {
    if (!IsWindow(hwnd)) return false;
    LONG_PTR exStyle = GetWindowLongPtr(hwnd, GWL_EXSTYLE);
    return (exStyle & WS_EX_TOPMOST) != 0;
}

// ��ⴰ���Ƿ�ȫ��
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

// ��С������
void MinimizeWindow(HWND hwnd) {
    if (hwnd != nullptr && IsWindow(hwnd)) {
        if (!ShowWindow(hwnd, SW_MINIMIZE)) {
            std::cerr << "�޷���С�����ڡ������룺" << GetLastError() << "\n";
            logger.Log("ERROR", "�޷���С�����ڡ������룺" + std::to_string(GetLastError()));
        }
    }
}

// ö�ٴ��ڻص�����
BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam) {
    DWORD targetProcessId = static_cast<DWORD>(lParam);
    DWORD processId;
    GetWindowThreadProcessId(hwnd, &processId);

    if (processId != targetProcessId) {
        return TRUE; // ����Ŀ�����Ĵ��ڣ�����ö��
    }

    if (IsWindowVisible(hwnd) && (IsWindowTopMost(hwnd) || IsWindowFullScreen(hwnd))) {
        MinimizeWindow(hwnd);
        wchar_t windowName[256];
        GetWindowTextW(hwnd, windowName, sizeof(windowName) / sizeof(wchar_t));
        std::wcout << L"����С��һ�����������Ĵ��ڣ�" << windowName << "\n";
        logger.Log("INFO", "����С��һ�����������Ĵ��ڣ�" + WideCharToMultiByteString(windowName));
    }

    return TRUE; // ����ö��
}

// ��ⴰ�ڵ��̺߳���
void DetectWindows(const std::atomic<bool>& running, DWORD targetProcessId, HWND hwnd) {
    while (running) {
        EnumWindows(EnumWindowsProc, static_cast<LPARAM>(targetProcessId));
        Sleep(200); // ÿ200������һ��
    }
}

// ��ȡĿ�����Ľ���ID
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
    logger.Log("INFO", "\n========+========\n��������");
    EnsureRunAsAdministrator();
    HWND hwnd = GetForegroundWindow();

    // ��ʼ������
    ConfigManager config;

    // ��ȡ��������
    std::string processName = config.Get("process_name", "StudentMain.exe");
    logger.Log("INFO", "��ȡ��������");
    std::wstring mythwarePath = MultiByteToWideCharString(config.Get("mythware_path", ""));  //����·��

    // ���·��δ���ã������Զ����
    if (mythwarePath.empty()) {
        mythwarePath = DetectMythwarePath();
        if (!mythwarePath.empty()) {
            config.Set("mythware_path", WideCharToMultiByteString(mythwarePath));
        }
    }

    // ���ô����ö�
    SetWindowPos(hwnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);

    // �Զ��������
    std::atomic<bool> running(config.Get("auto_start", "false") == "true");
    std::thread detectThread;

    if (running) {
        DWORD pid = GetProcessIdByName(processName);
        if (pid != 0) {
            detectThread = std::thread(DetectWindows, std::ref(running), pid, hwnd);
            logger.Log("INFO", "�Զ��������ڼ��" + std::to_string(pid));
        }
        else {
            running = false;
            config.Set("auto_start", "false");
            logger.Log("WARNING", "�Զ�����ʧ�ܣ�δ�ҵ�����");
        }
    }

TiaoZhuan:
    std::cout << "�汾�ţ�2.6.5";
    std::cout << "��ӭʹ��jiyuunlock\n";
    std::cout << "��������������help ������ֲ�\n\n";

    DWORD targetProcessId = GetProcessIdByName(processName);// ��ȡ����ID
    if (targetProcessId == 0) {
        std::cout << "���棺δ��⵽����δ����\n";
        logger.Log("WARNING", "δ��⵽Ŀ�����" + std::to_string(targetProcessId));
        std::cout << "�����輫����������\n";
        std::cout << "�������������";
        std::cin >> processName;
        goto TiaoZhuan;
    }

    std::cout << "��⵽����Ľ���IDΪ��" << targetProcessId << "\n";
    logger.Log("INFO", "��⵽����ID: " + std::to_string(targetProcessId));

    std::cout << "����������: ";

    while (true) {
        SetWindowPos(hwnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
        std::string command;
        std::cin >> command;

        if (command == "windowsopen") {
            DWORD targetProcessId = GetProcessIdByName(processName);// ��ȡ����ID
            if (!running) {
                running = true;
                config.Set("auto_start", "true");
                if (detectThread.joinable()) detectThread.join(); // ȷ���̰߳�ȫ
                detectThread = std::thread(DetectWindows, std::ref(running), targetProcessId, hwnd);
                std::cout << "���ڼ���ѿ���\n";
                logger.Log("INFO", "���ڼ���ѿ���");
            }
            else {
                std::cout << "�������������\n";
                logger.Log("WARNING", "�ظ���������");
            }
        }
        else if (command == "windowsclose") {
            DWORD targetProcessId = GetProcessIdByName(processName);
            if (running) {
                running = false;
                config.Set("auto_start", "false");
                if (detectThread.joinable()) {
                    detectThread.join();
                    std::cout << "���ڼ���ѹر�\n";
                    logger.Log("INFO", "���ڼ���ѹر�");
                }
            }
            else {
                std::cout << "���δ����\n";
                logger.Log("WARNING", "���Թر�δ���еļ��");
            }
        }
        else if (command == "exit") {
            DWORD targetProcessId = GetProcessIdByName(processName);
            if (running) {
                running = false;
                config.Set("auto_start", "false");
                if (detectThread.joinable()) detectThread.join();
            }
            std::cout << "�˳�����\n";
            logger.Log("INFO", "�û��˳�����");
            break;
        }
        else if (command == "kill") {
            DWORD targetProcessId = GetProcessIdByName(processName);
            if (taskkill(targetProcessId)) {
                std::cout << "������ֹ�ɹ�\n";
                logger.Log("INFO", "�ɹ���ֹ����"+std::to_string(targetProcessId));
                goto TiaoZhuan; // ���¼�����״̬
            }
            else {
                std::cout << "��ֹʧ��\n";
                logger.Log("ERROR", "��ֹ����ʧ��"+std::to_string(GetLastError()));
            }
        }
        else if (command == "del") {
            DWORD targetProcessId = GetProcessIdByName(processName);
            const TCHAR* directoryPath = _T("C:\\Program Files (x86)\\Mythware");
            DeleteAllFilesInDirectory(directoryPath);
            logger.Log("WARNING", "ִ��ɾ������: " + WideCharToMultiByteString(directoryPath));
        }
        else if (command == "top") {
            std::string subcmd;
            std::cin >> subcmd;
            if (subcmd == "s") {
                int time = 0;
                std::cout << "�������ö�ѭ�����ʱ�䣨����,Ĭ��Ϊ0��������Դ��: ";
                std::cin >> time;
                if (!topRunning) {
                    topRunning = true;
                    if (topThread.joinable()) topThread.join();
                    topThread = std::thread(topWindow, std::ref(topRunning), hwnd, time);
                    std::cout << "���ڳ����ö��ѿ���\n";
                    logger.Log("INFO", "���ڳ����ö�����");
                }
                else {
                    std::cout << "�ö���������������\n";
                    logger.Log("WARNING", "�ظ������ö�����");
                }
            }
            else if (subcmd == "c") {
                if (topRunning) {
                    topRunning = false;
                    if (topThread.joinable()) {
                        topThread.join();
                        std::cout << "���ڳ����ö��ѹر�\n";
                        logger.Log("INFO", "���ڳ����ö��ر�");
                    }
                }
                else {
                    std::cout << "�ö�����δ����\n";
                    logger.Log("WARNING", "���Թر�δ���е��ö�����");
                }
            }
            else {
                std::cout << "��Ч��top���ʹ��top s��top c\n";
                logger.Log("WARNING", "��Ч��top������: " + subcmd);
            }
        }
        else if (command == "putRod") {
            std::string path;
            std::cout << "�����뼫��·��: ";
            std::cin >> path;
            config.Set("path", path);
            std::cout << "����·��������\n";
            logger.Log("INFO", "���ü���·��: " + path);
        }
        else if (command == "putName") {
            std::string name;
            std::cout << "�����뼫����������: ";
            std::cin >> name;
            config.Set("name", name);
            std::cout << "������������������\n";
            DetectMythwarePath();
            logger.Log("INFO", "���ü�����������: " + name);
        }
        else if (command == "unloadhook") {
            DWORD targetProcessId = GetProcessIdByName(processName);
            if (unloadHook(targetProcessId)) {
                std::cout << "ж�ع��ӳɹ�\n";
            }
            else {
                std::cerr << "ж�ع���ʧ��\n";
            }
        }
        else if (command == "help") {
            DWORD targetProcessId = GetProcessIdByName(processName);
            std::cout << "�����б�:\n"
                << "  windowsopen  - �������ڼ��(����ʦ����Ļ�㲥�ͺ���ʧЧ)\n"
                << "  windowsclose - �رմ��ڼ��\n"
                << "  top s        - ���������ö�(��ʹ���������˳�����������ʾ)\n"
                << "  top c        - �رճ����ö�\n"
                << "  kill         - ��ֹ�������(�رճ���,��������ʦ����)\n"
                << "  del          - ɾ�������ļ�\n"
                << "  exit         - �˳�����(�˳��˳���)\n"
                << "  putRod       - ���ü���·��,Ĭ��ΪC:\\Program Files (x86)\\Mythware\n"
                << "  putName      - ���ü�����������,Ĭ��ΪStudentMain.exe\n"
                << "  unloadhook   - ж�ع���(��������޷���������ִ�д�ָ��)\n";
            logger.Log("INFO", "�鿴������Ϣ");
        }
        else {
            std::cout << "��Ч�������help�鿴����\n";
            logger.Log("WARNING", "��Ч����: " + command);
        }
    }

    logger.Log("INFO", "���������˳�");
    return 0;
}