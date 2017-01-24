#include <iostream>
#include <codecvt>
#include <Windows.h>
#include <TlHelp32.h>

using namespace std;

void EnablePrivilege(wstring privilegeName)
{
	HANDLE hToken;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken))
		throw runtime_error("OpenProcessToken failed: " + to_string(GetLastError()));

	LUID luid;
	if (!LookupPrivilegeValueW(nullptr, privilegeName.c_str(), &luid))
	{
		CloseHandle(hToken);
		throw runtime_error("LookupPrivilegeValue failed: " + to_string(GetLastError()));
	}

	TOKEN_PRIVILEGES tp;
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr))
	{
		CloseHandle(hToken);
		throw runtime_error("AdjustTokenPrivilege failed: " + to_string(GetLastError()));
	}

	CloseHandle(hToken);
}

DWORD GetProcessIdByName(wstring processName)
{
	HANDLE hSnapshot;
	if ((hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)) == INVALID_HANDLE_VALUE)
	{
		throw runtime_error("CreateToolhelp32Snapshot failed: " + to_string(GetLastError()));
	}

	DWORD pid = -1;
	PROCESSENTRY32W pe;
	ZeroMemory(&pe, sizeof(PROCESSENTRY32W));
	pe.dwSize = sizeof(PROCESSENTRY32W);
	if (Process32FirstW(hSnapshot, &pe))
	{
		while (Process32NextW(hSnapshot, &pe))
		{
			if (pe.szExeFile == processName)
			{
				pid = pe.th32ProcessID;
				break;
			}
		}
	}
	else
	{
		CloseHandle(hSnapshot);
		throw runtime_error("Process32First failed: " + to_string(GetLastError()));
	}

	if (pid == -1)
	{
		CloseHandle(hSnapshot);
		throw runtime_error("process not found: " + wstring_convert<codecvt_utf8<wchar_t>>().to_bytes(processName));
	}

	CloseHandle(hSnapshot);
	return pid;
}

void ImpersonateSystem()
{
	auto systemPid = GetProcessIdByName(L"winlogon.exe");
	HANDLE hSystemProcess;
	if ((hSystemProcess = OpenProcess(
		PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION,
		                  FALSE,
		                  systemPid)) == nullptr)
	{
		throw runtime_error("OpenProcess failed (winlogon.exe): " + to_string(GetLastError()));
	}

	HANDLE hSystemToken;
	if (!OpenProcessToken(
		hSystemProcess,
		MAXIMUM_ALLOWED,
		&hSystemToken))
	{
		CloseHandle(hSystemProcess);
		throw runtime_error("OpenProcessToken failed (winlogon.exe): " + to_string(GetLastError()));
	}

	HANDLE hDupToken;
	SECURITY_ATTRIBUTES tokenAttributes;
	tokenAttributes.nLength = sizeof(SECURITY_ATTRIBUTES);
	tokenAttributes.lpSecurityDescriptor = nullptr;
	tokenAttributes.bInheritHandle = FALSE;
	if (!DuplicateTokenEx(
		hSystemToken,
		MAXIMUM_ALLOWED,
		&tokenAttributes,
		SecurityImpersonation,
		TokenImpersonation,
		&hDupToken))
	{
		CloseHandle(hSystemToken);
		throw runtime_error("DuplicateTokenEx failed (winlogon.exe): " + to_string(GetLastError()));
	}

	if (!ImpersonateLoggedOnUser(hDupToken))
	{
		CloseHandle(hDupToken);
		CloseHandle(hSystemToken);
		throw runtime_error("ImpersonateLoggedOnUser failed: " + to_string(GetLastError()));
	}

	CloseHandle(hDupToken);
	CloseHandle(hSystemToken);
}

int StartTrustedInstallerService()
{
	SC_HANDLE hSCManager;
	if ((hSCManager = OpenSCManagerW(
		nullptr,
		SERVICES_ACTIVE_DATABASE,
		GENERIC_EXECUTE)) == nullptr)
	{
		throw runtime_error("OpenSCManager failed: " + to_string(GetLastError()));
	}

	SC_HANDLE hService;
	if ((hService = OpenServiceW(
		hSCManager,
		L"TrustedInstaller",
		GENERIC_READ | GENERIC_EXECUTE)) == nullptr)
	{
		CloseServiceHandle(hSCManager);
		throw runtime_error("OpenService failed: " + to_string(GetLastError()));
	}

	SERVICE_STATUS_PROCESS statusBuffer;
	DWORD bytesNeeded;
	while (QueryServiceStatusEx(
		hService,
		SC_STATUS_PROCESS_INFO,
		reinterpret_cast<LPBYTE>(&statusBuffer),
		sizeof(SERVICE_STATUS_PROCESS),
		&bytesNeeded))
	{
		if (statusBuffer.dwCurrentState == SERVICE_STOPPED)
		{
			if (!StartServiceW(hService, 0, nullptr))
			{
				CloseServiceHandle(hService);
				CloseServiceHandle(hSCManager);
				throw runtime_error("StartService failed: " + to_string(GetLastError()));
			}
		}
		if (statusBuffer.dwCurrentState == SERVICE_START_PENDING ||
			statusBuffer.dwCurrentState == SERVICE_STOP_PENDING)
		{
			Sleep(statusBuffer.dwWaitHint);
			continue;
		}
		if (statusBuffer.dwCurrentState == SERVICE_RUNNING)
		{
			CloseServiceHandle(hService);
			CloseServiceHandle(hSCManager);
			return statusBuffer.dwProcessId;
		}
	}
	CloseServiceHandle(hService);
	CloseServiceHandle(hSCManager);
	throw runtime_error("QueryServiceStatusEx failed: " + to_string(GetLastError()));
}

void CreateProcessAsTrustedInstaller(DWORD pid, wstring commandLine)
{
	EnablePrivilege(SE_DEBUG_NAME);
	EnablePrivilege(SE_IMPERSONATE_NAME);
	ImpersonateSystem();

	HANDLE hTIProcess;
	if ((hTIProcess = OpenProcess(
		PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION,
		                  FALSE,
		                  pid)) == nullptr)
	{
		throw runtime_error("OpenProcess failed (TrustedInstaller.exe): " + to_string(GetLastError()));
	}

	HANDLE hTIToken;
	if (!OpenProcessToken(
		hTIProcess,
		MAXIMUM_ALLOWED,
		&hTIToken))
	{
		CloseHandle(hTIProcess);
		throw runtime_error("OpenProcessToken failed (TrustedInstaller.exe): " + to_string(GetLastError()));
	}

	HANDLE hDupToken;
	SECURITY_ATTRIBUTES tokenAttributes;
	tokenAttributes.nLength = sizeof(SECURITY_ATTRIBUTES);
	tokenAttributes.lpSecurityDescriptor = nullptr;
	tokenAttributes.bInheritHandle = FALSE;
	if (!DuplicateTokenEx(
		hTIToken,
		MAXIMUM_ALLOWED,
		&tokenAttributes,
		SecurityImpersonation,
		TokenImpersonation,
		&hDupToken))
	{
		CloseHandle(hTIToken);
		throw runtime_error("DuplicateTokenEx failed (TrustedInstaller.exe): " + to_string(GetLastError()));
	}

	STARTUPINFOW startupInfo;
	ZeroMemory(&startupInfo, sizeof(STARTUPINFOW));
	startupInfo.lpDesktop = L"Winsta0\\Default";
	PROCESS_INFORMATION processInfo;
	ZeroMemory(&processInfo, sizeof(PROCESS_INFORMATION));
	if (!CreateProcessWithTokenW(
		hDupToken,
		LOGON_WITH_PROFILE,
		nullptr,
		const_cast<LPWSTR>(commandLine.c_str()),
		CREATE_UNICODE_ENVIRONMENT,
		nullptr,
		nullptr,
		&startupInfo,
		&processInfo))
	{
		throw runtime_error("CreateProcessWithTokenW failed: " + to_string(GetLastError()));
	}
}

int wmain(int argc, wchar_t* argv[])
{
	wstring commandLine;
	if (argc == 1)
	{
		commandLine = L"cmd.exe";
	}
	else if (argc == 2)
	{
		commandLine = argv[1];
	}
	else
	{
		wcout << L"Error: invalid argument." << endl;
		return 0;
	}

	try
	{
		auto pid = StartTrustedInstallerService();
		CreateProcessAsTrustedInstaller(pid, L"\"" + commandLine + L"\"");
	}
	catch (exception e)
	{
		wcout << e.what() << endl;
	}

	return 0;
}
