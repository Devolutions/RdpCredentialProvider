
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
