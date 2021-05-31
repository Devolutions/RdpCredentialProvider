
#include <tchar.h>
#include <stdio.h>
#include <string.h>
#include <windows.h>
#include <wincred.h>

int WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd)
{
	DWORD status;
	BOOL fSave = FALSE;
	ULONG ulAuthPackage = 0;
	LPVOID authBuffer;
	ULONG authBufferSize = 0;
	CREDUI_INFO credUiInfo;

	credUiInfo.pszCaptionText = _T("Rdp Credential Provider");
	credUiInfo.pszMessageText = _T("Please enter your remote desktop credentials");
	credUiInfo.cbSize = sizeof(CREDUI_INFO);
	credUiInfo.hbmBanner = NULL;
	credUiInfo.hwndParent = NULL;

	status = CredUIPromptForWindowsCredentials(&credUiInfo, 0, &ulAuthPackage, NULL, 0, &authBuffer, &authBufferSize, &fSave, 0);

	_tprintf(_T("CredUIPromptForWindowsCredentials status: %d\n"), status);

	return 0;
}
