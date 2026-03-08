// KeyAuth-DLL-Injector-Base.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

// KeyAuth DLL Injector Base - Made by @ew.exe //

#include <Windows.h>
#include "KeyAuth/auth.hpp"
#include <string>
#include <thread>
#include "KeyAuth/utils.hpp"
#include "KeyAuth/skStr.h"
#include <iostream>

#include <ctime>
#include <cstdlib>
#include <TlHelp32.h>

std::string tm_to_readable_time(tm ctx);
static std::time_t string_to_timet(std::string timestamp);
static std::tm timet_to_tm(time_t timestamp);
const std::string compilation_date = (std::string)skCrypt(__DATE__);
const std::string compilation_time = (std::string)skCrypt(__TIME__);
void sessionStatus();

using namespace KeyAuth;

// input your KeyAuth credentials here below

std::string name = skCrypt("").decrypt();
std::string ownerid = skCrypt("").decrypt();
std::string version = skCrypt("1.0").decrypt();
std::string url = skCrypt("https://keyauth.win/api/1.3/").decrypt();
std::string path = skCrypt("").decrypt();

api KeyAuthApp(name, ownerid, version, url, path);

// function to get process ID of a process by its name

DWORD GetProcID(const char* procName)
{
    DWORD procID = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE)
    {
        PROCESSENTRY32 procEntry;
        procEntry.dwSize = sizeof(procEntry);
        if (Process32First(hSnap, &procEntry))
        {
            do
            {
                if (!_stricmp(procEntry.szExeFile, procName))
                {
                    procID = procEntry.th32ProcessID;
                    break;
                }
            } while (Process32Next(hSnap, &procEntry));
        }
    }
    CloseHandle(hSnap);
    return procID;
}

// Main function - entry point of the program

int main()
{

    // default keyauth console title:
    // std::string consoleTitle = skCrypt("Loader - Built at:  ").decrypt() + compilation_date + " " + compilation_time;
    // SetConsoleTitleA(consoleTitle.c_str());



    // Seed the random number generator with current time
    srand(static_cast<unsigned int>(time(nullptr)));

    std::string title = "";
    int length = 12;

    // Generate a random string of letters and numbers
    for (int i = 0; i < length; i++) 
    {
        if (rand() % 2 == 0) {
            title += static_cast<char>(rand() % 26 + 'a');
        }
        else {
            title += std::to_string(rand() % 10);
        }
    }

	// Set the console title to the random string
    SetConsoleTitleA(title.c_str());

    std::cout << skCrypt("\n\n Connecting..");

    KeyAuthApp.init();
    if (!KeyAuthApp.response.success)
    {
        std::cout << skCrypt("\n Status: ") << KeyAuthApp.response.message;
        Sleep(1500);
        exit(1);
    }

    std::string username, password, key, TfaCode; // keep this before the auto-login with saved file.
    // because if you don't and the user has 2FA on, then they won't be asked for 2FA code and can't login.

    if (std::filesystem::exists("test.json")) //change test.txt to the path of your file :smile:
    {
        if (!CheckIfJsonKeyExists("test.json", "username"))
        {
            key = ReadFromJson("test.json", "license");
            KeyAuthApp.license(key);
        }
        else
        {
            username = ReadFromJson("test.json", "username");
            password = ReadFromJson("test.json", "password");
            KeyAuthApp.login(username, password);
        }
    }
    else
    {
        std::cout << skCrypt("\n\n [1] Login\n [2] Register\n [3] Upgrade\n [4] License key only\n\n Choose option: ");

        int option;

        std::cin >> option;
        switch (option)
        {
        case 1:
            std::cout << skCrypt("\n\n Enter username: ");
            std::cin >> username;
            std::cout << skCrypt("\n Enter password: ");
            std::cin >> password;
            KeyAuthApp.login(username, password, "");
            break;
        case 2:
            std::cout << skCrypt("\n\n Enter username: ");
            std::cin >> username;
            std::cout << skCrypt("\n Enter password: ");
            std::cin >> password;
            std::cout << skCrypt("\n Enter license: ");
            std::cin >> key;
            KeyAuthApp.regstr(username, password, key);
            break;
        case 3:
            std::cout << skCrypt("\n\n Enter username: ");
            std::cin >> username;
            std::cout << skCrypt("\n Enter license: ");
            std::cin >> key;
            KeyAuthApp.upgrade(username, key);
            break;
        case 4:
            std::cout << skCrypt("\n Enter license: ");
            std::cin >> key;
            KeyAuthApp.license(key, "");
            break;
        default:
            std::cout << skCrypt("\n\n Status: Failure: Invalid Selection");
            Sleep(3000);
            exit(1);
        }
    }

    if (KeyAuthApp.response.message.empty()) exit(11);
    if (!KeyAuthApp.response.success)
    {
        if (KeyAuthApp.response.message == "2FA code required.") {
            if (username.empty() || password.empty()) {
                std::cout << skCrypt("\n Your account has 2FA enabled, please enter 6-digit code:");
                std::cin >> TfaCode;
                KeyAuthApp.license(key, TfaCode);
            }
            else {
                std::cout << skCrypt("\n Your account has 2FA enabled, please enter 6-digit code:");
                std::cin >> TfaCode;
                KeyAuthApp.login(username, password, TfaCode);
            }

            if (KeyAuthApp.response.message.empty()) exit(11);
            if (!KeyAuthApp.response.success) {
                std::cout << skCrypt("\n Status: ") << KeyAuthApp.response.message;
                std::remove("test.json");
                Sleep(1500);
                exit(1);
            }
        }
        else {
            std::cout << skCrypt("\n Status: ") << KeyAuthApp.response.message;
            std::remove("test.json");
            Sleep(1500);
            exit(1);
        }
    }

    if (username.empty() || password.empty())
    {
        WriteToJson("test.json", "license", key, false, "", "");
        std::cout << skCrypt("Successfully Created File For Auto Login");
    }
    else
    {
        WriteToJson("test.json", "username", username, true, "password", password);
        std::cout << skCrypt("Successfully Created File For Auto Login");
    }

    /*
    * Do NOT remove this checkAuthenticated() function.
    * It protects you from cracking, it would be NOT be a good idea to remove it
    */
    std::thread run(checkAuthenticated, ownerid);
    // do NOT remove checkAuthenticated(), it MUST stay for security reasons
    std::thread check(sessionStatus); // do NOT remove this function either.

    //enable 2FA 
    // KeyAuthApp.enable2fa(); you will need to ask for the code
    //enable 2fa without the need of asking for the code
    //KeyAuthApp.enable2fa().handleInput(KeyAuthApp);

    //disbale 2FA
    // KeyAuthApp.disable2fa();

    if (KeyAuthApp.user_data.username.empty()) exit(10);
    std::cout << skCrypt("\n User data:");
    std::cout << skCrypt("\n Username: ") << KeyAuthApp.user_data.username;
    std::cout << skCrypt("\n IP address: ") << KeyAuthApp.user_data.ip;
    std::cout << skCrypt("\n Hardware-Id: ") << KeyAuthApp.user_data.hwid;
    std::cout << skCrypt("\n Create date: ") << tm_to_readable_time(timet_to_tm(string_to_timet(KeyAuthApp.user_data.createdate)));
    std::cout << skCrypt("\n Last login: ") << tm_to_readable_time(timet_to_tm(string_to_timet(KeyAuthApp.user_data.lastlogin)));
    std::cout << skCrypt("\n Subscription(s): ");

    for (int i = 0; i < KeyAuthApp.user_data.subscriptions.size(); i++) {
        auto sub = KeyAuthApp.user_data.subscriptions.at(i);
        std::cout << skCrypt("\n name: ") << sub.name;
        std::cout << skCrypt(" : expiry: ") << tm_to_readable_time(timet_to_tm(string_to_timet(sub.expiry)));
    }

    std::cout << skCrypt("\n\n Status: ") << KeyAuthApp.response.message;

	// DLL Injection part - you can change the dll path and process name to your desired ones, also you can change the sleep timers if you want to make it faster or slower, it's up to you.

    std::cout << skCrypt("\n\n Finding Process...");
    Sleep(2000);


	// Dll Path and Process Name - change these to your desired ones
	const char* dllPath = "C:\\path\\to\\your\\dll.dll"; // change this to your dll path
    const char* procName = "process.exe"; // change this to your target process name
    DWORD procId = 0;


	// Loop until we get the process ID of the target process, this is useful in case the process is not open when we start the injector, so it keeps checking until it finds it.
    while (!procId)
    {
        procId = GetProcID(procName);
        Sleep(100);
    }


	// Once we have the process ID, we can proceed with the injection, you can change the sleep timers if you want to make it faster or slower, it's up to you.
    std::cout << skCrypt("\n\n Attached to Process!");
    Sleep(1000);

    std::cout << skCrypt("\n\n Cheat Injecting...");
    Sleep(10000);


	// The actual injection part, this is a very basic injection method, it allocates memory in the target process, writes the dll path to that memory, and then creates a remote thread that calls LoadLibraryA with the dll path as an argument, this causes the target process to load the dll and execute its code.
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, 0, procId);

    if (hProc && hProc != INVALID_HANDLE_VALUE)
    {
        void* loc = VirtualAllocEx(hProc, 0, MAX_PATH, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

        WriteProcessMemory(hProc, loc, dllPath, strlen(dllPath) + 1, 0);

        HANDLE hThread = CreateRemoteThread(hProc, 0, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, loc, 0, 0);

        if (hThread)
        {
            CloseHandle(hThread);
        }

        if (hProc)
        {
            CloseHandle(hProc);
        }
    }


	// Injection is done at this point, you can change the sleep timers if you want to make it faster or slower, it's up to you.
    std::cout << skCrypt("\n\n Cheat Injected!");
    Sleep(500);

    std::cout << skCrypt("\n\n Closing in five seconds...");
    Sleep(5000);

    return 0;
}


// This function is used to keep checking the session status, if you remove this then the sn gets terminated from anession won't be checked and if the sessioother location, then the user won't be logged out from the app, so it is recommended to keep this function as it is for security reasons.

void sessionStatus() {
    KeyAuthApp.check(true); // do NOT specify true usually, it is slower and will get you blocked from API
    if (!KeyAuthApp.response.success) {
        exit(0);
    }

    if (KeyAuthApp.response.isPaid) {
        while (true) {
            Sleep(20000); // this MUST be included or else you get blocked from API
            KeyAuthApp.check();
            if (!KeyAuthApp.response.success) {
                exit(0);
            }
        }
    }
}

// helper functions to convert time formats, you can ignore these

std::string tm_to_readable_time(tm ctx) {
    char buffer[80];

    strftime(buffer, sizeof(buffer), "%a %m/%d/%y %H:%M:%S %Z", &ctx);

    return std::string(buffer);
}

static std::time_t string_to_timet(std::string timestamp) {
    auto cv = strtol(timestamp.c_str(), NULL, 10); // long

    return (time_t)cv;
}

static std::tm timet_to_tm(time_t timestamp) {
    std::tm context;

    localtime_s(&context, &timestamp);

    return context;
}

