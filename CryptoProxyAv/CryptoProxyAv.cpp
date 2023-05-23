// CryptoProxyAv.cpp : Defines the entry point for the application.
//
#include "src\TodoServerApp.h"
#include <cpprest/http_listener.h>
#include <cpprest/json.h>
#include "framework.h"
#include "CryptoProxyAv.h"
#include <windows.h>
#include <shellapi.h>
#include <stdio.h>
#include <stdlib.h>
#include "src\crypto.h"
#include "src\helpers.h"
#include "src\crypto.h"

#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "cryptui.lib")
#pragma comment (lib, "Bcrypt.lib")
#pragma comment (lib, "Ncrypt.lib")


using namespace web;
using namespace http;
using namespace http::experimental::listener;

#define MAX_LOADSTRING 100

// Global Variables:
HINSTANCE hInst;                                // current instance
NOTIFYICONDATA iconTray;
WCHAR szTitle[MAX_LOADSTRING];                  // The title bar text
WCHAR szWindowClass[MAX_LOADSTRING];            // the main window class name
HTTPServer* httpServer;

// Forward declarations of functions included in this code module:
ATOM                MyRegisterClass(HINSTANCE hInstance);
BOOL                InitInstance(HINSTANCE, int);
LRESULT CALLBACK    WndProc(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK    About(HWND, UINT, WPARAM, LPARAM);

HTTPServer* startHttp();

int APIENTRY wWinMain(_In_ HINSTANCE hInstance,
                     _In_opt_ HINSTANCE hPrevInstance,
                     _In_ LPWSTR    lpCmdLine,
                     _In_ int       nCmdShow)
{

    //testBase64decode();
    // ¿Î„ÓËÚÏ˚: "—“¡ 1176.1",  "—“¡ 34.101.31", ÔÓ‚‡È‰Â:  L"Avest CNG Provider"
    //crypto::testHash(L"—“¡ 34.101.31", L"Avest CNG Provider");
    crypto::testSign(L"—“¡ 34.101.31", L"Avest CNG Provider");
    // crypto::enumStorageProviders();
    return 0;

    // OutputDebugString(L"Unicode\n");
    MSG msg;

    //# Allow only one instance to run
    CreateMutex(0, 0, L"CryptoProxyAv");
    if (GetLastError() == ERROR_ALREADY_EXISTS) return 0;

    // Initialize global strings
    MyRegisterClass(hInstance);

    // Perform application initialization:
    if (!InitInstance(hInstance, nCmdShow)) {
        return FALSE;
    }
    httpServer = startHttp();
    // Main message loop:
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    
    return msg.wParam;
}



//
//  FUNCTION: MyRegisterClass()
//
//  PURPOSE: Registers the window class.
//
ATOM MyRegisterClass(HINSTANCE hInstance)
{
    WNDCLASSEX wcex;

    memset(&wcex, 0, sizeof(WNDCLASSEX));
    wcex.cbSize = sizeof(WNDCLASSEX);
    wcex.lpfnWndProc = (WNDPROC)WndProc;
    wcex.hInstance = hInstance;
    wcex.lpszClassName = L"CryptoProxyAv";
    wcex.hbrBackground = GetSysColorBrush(COLOR_3DFACE);

    return RegisterClassEx(&wcex);

}

//
//   FUNCTION: InitInstance(HINSTANCE, int)
//
//   PURPOSE: Saves instance handle and creates main window
//
//   COMMENTS:
//
//        In this function, we save the instance handle in a global variable and
//        create and display the main program window.
//
BOOL InitInstance(HINSTANCE hInstance, int nCmdShow)
{
    HWND hWnd;

    hInst = hInstance; // Store instance handle in our global variable

    //# Create the hidden window
    hWnd = CreateWindow(L"CryptoProxyAv", L"", WS_OVERLAPPEDWINDOW, 0, 0, 0, 0, NULL, NULL, hInstance, NULL);

    if (!hWnd) {
        return FALSE;
    }


    iconTray.cbSize = sizeof(NOTIFYICONDATA);
    // iconTray.hIcon = LoadCursor(NULL, IDC_ARROW);	//# Passing cursor handle in place of icon
    iconTray.hIcon = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_ICON1));
    iconTray.hWnd = hWnd;
    wcscpy_s(iconTray.szTip, L"CryptoProxyAv");
    iconTray.uCallbackMessage = WM_TRAY;
    iconTray.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    iconTray.uID = 666;
    Shell_NotifyIcon(NIM_ADD, &iconTray);

    return TRUE;
}

//
//  FUNCTION: WndProc(HWND, UINT, WPARAM, LPARAM)
//
//  PURPOSE: Processes messages for the main window.
//
//  WM_COMMAND  - process the application menu
//  WM_PAINT    - Paint the main window
//  WM_DESTROY  - post a quit message and return
//
//
LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    POINT pt;
    HMENU hMenu;

    switch (message) {
    case WM_DESTROY:
        PostQuitMessage(0);
        break;

    case WM_TRAY:
        if (WM_RBUTTONDOWN == lParam)						//# Show menu
        {
            hMenu = CreatePopupMenu();
            AppendMenu(hMenu, MF_STRING, OPTION_ABOUT, L"About");
            AppendMenu(hMenu, MF_STRING, OPTION_EXIT, L"Exit");
            SetMenuDefaultItem(hMenu, 0, TRUE);

            SetForegroundWindow(hWnd);

            GetCursorPos(&pt);
            TrackPopupMenu(hMenu, TPM_RIGHTALIGN | TPM_BOTTOMALIGN | TPM_RIGHTBUTTON,
                pt.x, pt.y, 0, hWnd, NULL);
            DestroyMenu(hMenu);
            hMenu = NULL;

            PostMessage(hWnd, WM_NULL, 0, 0);
        }
        break;

    case WM_COMMAND:
        switch (LOWORD(wParam))						//# Menu option selected from tray menu
        {

        case OPTION_ABOUT:
            helpers::showVersion(const_cast<wchar_t*> (L"CryptoProxyAV version "));
            break;

        case OPTION_EXIT:
            Shell_NotifyIcon(NIM_DELETE, &iconTray);
            httpServer->stopAll(true);
            DestroyWindow(hWnd);
            break;

        default:
            return DefWindowProc(hWnd, message, wParam, lParam);
        }
        break;

    default:
        return DefWindowProc(hWnd, message, wParam, lParam);
    }

    return 0;

}

// Message handler for about box.
INT_PTR CALLBACK About(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    UNREFERENCED_PARAMETER(lParam);
    switch (message)
    {
    case WM_INITDIALOG:
        return (INT_PTR)TRUE;

    case WM_COMMAND:
        if (LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCANCEL)
        {
            EndDialog(hDlg, LOWORD(wParam));
            return (INT_PTR)TRUE;
        }
        break;
    }
    return (INT_PTR)FALSE;
}
