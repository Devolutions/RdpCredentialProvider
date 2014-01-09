
#include "helpers.h"

#include <intsafe.h>
#include <wincred.h>

HRESULT FieldDescriptorCoAllocCopy(const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR& rcpfd, CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** ppcpfd)
{
	HRESULT hr;
	DWORD cbStruct = sizeof(CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR);
	CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* pcpfd = (CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR*) CoTaskMemAlloc(cbStruct);

	if (pcpfd)
	{
		pcpfd->dwFieldID = rcpfd.dwFieldID;
		pcpfd->cpft = rcpfd.cpft;

		if (rcpfd.pszLabel)
		{
			hr = SHStrDupW(rcpfd.pszLabel, &pcpfd->pszLabel);
		}
		else
		{
			pcpfd->pszLabel = NULL;
			hr = S_OK;
		}
	}
	else
	{
		hr = E_OUTOFMEMORY;
	}

	if (SUCCEEDED(hr))
	{
		*ppcpfd = pcpfd;
	}
	else
	{
		CoTaskMemFree(pcpfd);  
		*ppcpfd = NULL;
	}

	return hr;
}

HRESULT FieldDescriptorCopy(const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR& rcpfd, CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* pcpfd)
{
	HRESULT hr;
	CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR cpfd;

	cpfd.dwFieldID = rcpfd.dwFieldID;
	cpfd.cpft = rcpfd.cpft;

	if (rcpfd.pszLabel)
	{
		hr = SHStrDupW(rcpfd.pszLabel, &cpfd.pszLabel);
	}
	else
	{
		cpfd.pszLabel = NULL;
		hr = S_OK;
	}

	if (SUCCEEDED(hr))
	{
		*pcpfd = cpfd;
	}

	return hr;
}

HRESULT UnicodeStringInitWithString(PWSTR pwz, UNICODE_STRING* pus)
{
	HRESULT hr;

	if (pwz)
	{
		size_t lenString;
		hr = StringCchLengthW(pwz, USHORT_MAX, &(lenString));

		if (SUCCEEDED(hr))
		{
			USHORT usCharCount;
			hr = SizeTToUShort(lenString, &usCharCount);

			if (SUCCEEDED(hr))
			{
				USHORT usSize;
				hr = SizeTToUShort(sizeof(WCHAR), &usSize);

				if (SUCCEEDED(hr))
				{
					hr = UShortMult(usCharCount, usSize, &(pus->Length)); // Explicitly NOT including NULL terminator

					if (SUCCEEDED(hr))
					{
						pus->MaximumLength = pus->Length;
						pus->Buffer = pwz;
						hr = S_OK;
					}
					else
					{
						hr = HRESULT_FROM_WIN32(ERROR_ARITHMETIC_OVERFLOW);
					}
				}
			}
		}
	}
	else
	{
		hr = E_INVALIDARG;
	}

	return hr;
}

static void _UnicodeStringPackedUnicodeStringCopy(const UNICODE_STRING& rus, PWSTR pwzBuffer, UNICODE_STRING* pus)
{
	pus->Length = rus.Length;
	pus->MaximumLength = rus.Length;
	pus->Buffer = pwzBuffer;

	CopyMemory(pus->Buffer, rus.Buffer, pus->Length);
}

HRESULT KerbInteractiveUnlockLogonInit(PWSTR pwzDomain, PWSTR pwzUsername, PWSTR pwzPassword, CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, KERB_INTERACTIVE_UNLOCK_LOGON* pkiul)
{
	KERB_INTERACTIVE_UNLOCK_LOGON kiul;
	ZeroMemory(&kiul, sizeof(kiul));

	KERB_INTERACTIVE_LOGON* pkil = &kiul.Logon;

	HRESULT hr = UnicodeStringInitWithString(pwzDomain, &pkil->LogonDomainName);

	if (SUCCEEDED(hr))
	{
		hr = UnicodeStringInitWithString(pwzUsername, &pkil->UserName);

		if (SUCCEEDED(hr))
		{
			if (SUCCEEDED(hr))
			{
				hr = UnicodeStringInitWithString(pwzPassword, &pkil->Password);
			}

			if (SUCCEEDED(hr))
			{
				switch (cpus)
				{
				case CPUS_UNLOCK_WORKSTATION:
					pkil->MessageType = KerbWorkstationUnlockLogon;
					hr = S_OK;
					break;

				case CPUS_LOGON:
					pkil->MessageType = KerbInteractiveLogon;
					hr = S_OK;
					break;

				case CPUS_CREDUI:
					pkil->MessageType = (KERB_LOGON_SUBMIT_TYPE) 0;
					hr = S_OK;
					break;

				default:
					hr = E_FAIL;
					break;
				}

				if (SUCCEEDED(hr))
				{
					CopyMemory(pkiul, &kiul, sizeof(*pkiul));
				}
			}
		}
	}

	return hr;
}

HRESULT KerbInteractiveUnlockLogonPack(const KERB_INTERACTIVE_UNLOCK_LOGON& rkiulIn, BYTE** prgb, DWORD* pcb)
{
	HRESULT hr;

	const KERB_INTERACTIVE_LOGON* pkilIn = &rkiulIn.Logon;

	DWORD cb = sizeof(rkiulIn) +
		pkilIn->LogonDomainName.Length +
		pkilIn->UserName.Length +
		pkilIn->Password.Length;

	KERB_INTERACTIVE_UNLOCK_LOGON* pkiulOut = (KERB_INTERACTIVE_UNLOCK_LOGON*)CoTaskMemAlloc(cb);

	if (pkiulOut)
	{
		ZeroMemory(&pkiulOut->LogonId, sizeof(LUID));

		BYTE* pbBuffer = (BYTE*) pkiulOut + sizeof(*pkiulOut);

		KERB_INTERACTIVE_LOGON* pkilOut = &pkiulOut->Logon;

		pkilOut->MessageType = pkilIn->MessageType;

		_UnicodeStringPackedUnicodeStringCopy(pkilIn->LogonDomainName, (PWSTR) pbBuffer, &pkilOut->LogonDomainName);
		pkilOut->LogonDomainName.Buffer = (PWSTR) (pbBuffer - (BYTE*) pkiulOut);
		pbBuffer += pkilOut->LogonDomainName.Length;

		_UnicodeStringPackedUnicodeStringCopy(pkilIn->UserName, (PWSTR) pbBuffer, &pkilOut->UserName);
		pkilOut->UserName.Buffer = (PWSTR) (pbBuffer - (BYTE*) pkiulOut);
		pbBuffer += pkilOut->UserName.Length;

		_UnicodeStringPackedUnicodeStringCopy(pkilIn->Password, (PWSTR) pbBuffer, &pkilOut->Password);
		pkilOut->Password.Buffer = (PWSTR) (pbBuffer - (BYTE*) pkiulOut);

		*prgb = (BYTE*) pkiulOut;
		*pcb = cb;

		hr = S_OK;
	}
	else
	{
		hr = E_OUTOFMEMORY;
	}

	return hr;
}

void KerbInteractiveUnlockLogonUnpackInPlace(__inout_bcount(cb) KERB_INTERACTIVE_UNLOCK_LOGON* pkiul)
{
	KERB_INTERACTIVE_LOGON* pkil = &pkiul->Logon;

	pkil->LogonDomainName.Buffer = pkil->LogonDomainName.Buffer
		? (PWSTR)((BYTE*)pkiul + (ULONG_PTR)pkil->LogonDomainName.Buffer)
		: NULL;

	pkil->UserName.Buffer = pkil->UserName.Buffer
		? (PWSTR)((BYTE*)pkiul + (ULONG_PTR)pkil->UserName.Buffer)
		: NULL;

	pkil->Password.Buffer = pkil->Password.Buffer 
		? (PWSTR)((BYTE*)pkiul + (ULONG_PTR)pkil->Password.Buffer)
		: NULL;
}

HRESULT LsaInitString(PSTRING pszDestinationString, PCSTR pszSourceString)
{
	size_t cchLength;
	HRESULT hr = StringCchLength(pszSourceString, USHORT_MAX, &cchLength);

	if (SUCCEEDED(hr))
	{
		USHORT usLength;
		hr = SizeTToUShort(cchLength, &usLength);

		if (SUCCEEDED(hr))
		{
			pszDestinationString->Buffer = (PCHAR)pszSourceString;
			pszDestinationString->Length = usLength;
			pszDestinationString->MaximumLength = pszDestinationString->Length+1;
			hr = S_OK;
		}
	}
	return hr;
}

HRESULT RetrieveNegotiateAuthPackage(ULONG* pulAuthPackage)
{
	HRESULT hr;
	HANDLE hLsa;

	NTSTATUS status = LsaConnectUntrusted(&hLsa);

	if (SUCCEEDED(HRESULT_FROM_NT(status)))
	{

		ULONG ulAuthPackage;
		LSA_STRING lsaszKerberosName;
		LsaInitString(&lsaszKerberosName, NEGOSSP_NAME);

		status = LsaLookupAuthenticationPackage(hLsa, &lsaszKerberosName, &ulAuthPackage);

		if (SUCCEEDED(HRESULT_FROM_NT(status)))
		{
			*pulAuthPackage = ulAuthPackage;
			hr = S_OK;
		}
		else
		{
			hr = HRESULT_FROM_NT(status);
		}

		LsaDeregisterLogonProcess(hLsa);
	}
	else
	{
		hr= HRESULT_FROM_NT(status);
	}

	return hr;
}

static HRESULT ProtectAndCopyString(PWSTR pwzToProtect, PWSTR* ppwzProtected)
{
	*ppwzProtected = NULL;

	HRESULT hr = E_FAIL;
	DWORD cchProtected = 0;

	if (!CredProtectW(FALSE, pwzToProtect, (DWORD) wcslen(pwzToProtect) + 1, NULL, &cchProtected, NULL))
	{
		DWORD dwErr = GetLastError();

		if ((ERROR_INSUFFICIENT_BUFFER == dwErr) && (0 < cchProtected))
		{
			PWSTR pwzProtected = (PWSTR) CoTaskMemAlloc(cchProtected * sizeof(WCHAR));

			if (pwzProtected)
			{
				if (CredProtectW(FALSE, pwzToProtect, (DWORD) wcslen(pwzToProtect) + 1, pwzProtected, &cchProtected, NULL))
				{
					*ppwzProtected = pwzProtected;
					hr = S_OK;
				}
				else
				{
					CoTaskMemFree(pwzProtected);

					dwErr = GetLastError();
					hr = HRESULT_FROM_WIN32(dwErr);
				}
			}
			else
			{
				hr = E_OUTOFMEMORY;
			}
		}
		else
		{
			hr = HRESULT_FROM_WIN32(dwErr);
		}
	}

	return hr;
}

HRESULT ProtectIfNecessaryAndCopyPassword(PWSTR pwzPassword, CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, PWSTR* ppwzProtectedPassword)
{
	*ppwzProtectedPassword = NULL;

	HRESULT hr;

	if (pwzPassword && *pwzPassword)
	{
		bool bCredAlreadyEncrypted = false;
		CRED_PROTECTION_TYPE protectionType;

		if (CredIsProtectedW(pwzPassword, &protectionType))
		{
			if (CredUnprotected != protectionType)
			{
				bCredAlreadyEncrypted = true;
			}
		}

		if (CPUS_CREDUI == cpus || bCredAlreadyEncrypted)
		{
			hr = SHStrDupW(pwzPassword, ppwzProtectedPassword);
		}
		else
		{
			hr = ProtectAndCopyString(pwzPassword, ppwzProtectedPassword);
		}
	}
	else
	{
		hr = SHStrDupW(L"", ppwzProtectedPassword);
	}

	return hr;
}

int ConvertToUnicode(UINT CodePage, DWORD dwFlags, LPCSTR lpMultiByteStr,
		int cbMultiByte, LPWSTR* lpWideCharStr, int cchWideChar)
{
	int status;
	BOOL allocate = FALSE;

	if (!lpMultiByteStr)
		return 0;

	if (!lpWideCharStr)
		return 0;

	if (cbMultiByte == -1)
		cbMultiByte = (int) strlen(lpMultiByteStr) + 1;

	if (cchWideChar == 0)
	{
		cchWideChar = MultiByteToWideChar(CodePage, dwFlags, lpMultiByteStr, cbMultiByte, NULL, 0);
		allocate = TRUE;
	}

	if (cchWideChar < 1)
		return 0;

	if (!(*lpWideCharStr))
		allocate = TRUE;

	if (allocate)
		*lpWideCharStr = (LPWSTR) malloc(cchWideChar * sizeof(WCHAR));

	status = MultiByteToWideChar(CodePage, dwFlags, lpMultiByteStr, cbMultiByte, *lpWideCharStr, cchWideChar);

	if (status != cchWideChar)
		status = 0;

	return status;
}

int ConvertFromUnicode(UINT CodePage, DWORD dwFlags, LPCWSTR lpWideCharStr, int cchWideChar,
		LPSTR* lpMultiByteStr, int cbMultiByte, LPCSTR lpDefaultChar, LPBOOL lpUsedDefaultChar)
{
	int status;
	BOOL allocate = FALSE;

	if (!lpWideCharStr)
		return 0;

	if (!lpMultiByteStr)
		return 0;

	if (cchWideChar == -1)
		cchWideChar = (int) wcslen(lpWideCharStr) + 1;

	if (cbMultiByte == 0)
	{
		cbMultiByte = WideCharToMultiByte(CodePage, dwFlags, lpWideCharStr, cchWideChar, NULL, 0, NULL, NULL);
		allocate = TRUE;
	}

	if (cbMultiByte < 1)
		return 0;

	if (!(*lpMultiByteStr))
		allocate = TRUE;

	if (allocate)
	{
		*lpMultiByteStr = (LPSTR) malloc(cbMultiByte + 1);
		ZeroMemory(*lpMultiByteStr, cbMultiByte + 1);
	}

	status = WideCharToMultiByte(CodePage, dwFlags, lpWideCharStr, cchWideChar,
			*lpMultiByteStr, cbMultiByte, lpDefaultChar, lpUsedDefaultChar);

	if (status != cbMultiByte)
		status = 0;

	if ((status <= 0) && allocate)
	{
		free(*lpMultiByteStr);
		*lpMultiByteStr = NULL;
	}

	return status;
}

/* Logger Class */

CLogFile::CLogFile()
{
	m_enabled = true;

#ifndef RDPCREDPROV_LOGGING
	m_enabled = false;
#endif
}

CLogFile::~CLogFile()
{
	if (m_enabled)
		CloseFile();
}

void CLogFile::OpenFile(LPCTSTR strFile, bool bAppend, long lTruncate)
{
	m_lTruncate = lTruncate;

	if (!m_enabled)
		return;

	memcpy(m_filename, strFile, _tcslen(strFile));

	TCHAR szFile[MAX_PATH + 1];

	if (_tcslen(strFile) > 3 && strFile[1] != ':')
	{
		::GetModuleFileName(NULL, szFile, MAX_PATH);
		
		long llength = (long) _tcslen(szFile);
		TCHAR* pcat = szFile + (llength - 1);

		while (llength--)
		{
			pcat--;

			if (*pcat == '\\')
				break;
		}

		if (*pcat == '\\')
		{
			pcat++;
			_tcscpy(pcat, strFile);
		}
		else
		{
			_tcscpy(szFile, strFile);
		}
	}
	else
	{
		_tcscpy(szFile, strFile);
	}

	m_pLogFile = fopen(szFile, bAppend ? "a" : "w");

	if (!m_pLogFile)
	{
		CreateDirectories(szFile);
		m_pLogFile = fopen(szFile, bAppend ? "a" : "w");
	}

	InitializeCriticalSection(&m_cs);
}

void CLogFile::CloseFile()
{
	if (!m_enabled)
		return;

	if (m_pLogFile)
	{
		fclose(m_pLogFile);
	}

	DeleteCriticalSection(&m_cs);
}

void CLogFile::CreateDirectories(LPCTSTR filename)
{
	char drivename[4];
	char path[MAX_PATH + 1];
	char name[MAX_PATH + 1];
	char ext[MAX_PATH + 1];
	char seps[] = "/\\";
	char* token;

	if (!m_enabled)
		return;

	_splitpath(filename, drivename, path, name, ext);

	sprintf(drivename, "%s\\", drivename);
	_chdir(drivename);

	token = strtok(path, seps);

	while (token != NULL)
	{
		if (_chdir(token) == -1)	
		{
			_mkdir(token);
			_chdir(token);
		}

		token = strtok(NULL, seps);
	}
}

void CLogFile::Write(LPCTSTR pszFormat, ...)
{
	if (!m_enabled)
		return;

	if (!m_pLogFile)
		return;

	EnterCriticalSection(&m_cs);
	
	TCHAR szLog[256];
	va_list argList;
	va_start(argList, pszFormat);
	vsprintf(szLog, pszFormat, argList);
	va_end(argList);

	SYSTEMTIME time;
	::GetLocalTime(&time);
	TCHAR szLine[256];

	sprintf(szLine, "%04d/%02d/%02d %02d:%02d:%02d: %s\n",
		time.wYear, time.wMonth, time.wDay,
		time.wHour, time.wMinute, time.wSecond, szLog);

	fputs(szLine, m_pLogFile);

	fflush(m_pLogFile);

	LeaveCriticalSection(&m_cs);
}
