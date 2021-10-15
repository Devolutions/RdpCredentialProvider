
#include <credentialprovider.h>
#include "RdpProvider.h"
#include "RdpCredential.h"
#include "helpers.h"
#include "guid.h"

CLogFile log;

RdpProvider::RdpProvider():
	_cRef(1),
	_pkiulSetSerialization(NULL),
	_dwNumCreds(0),
	_bAutoSubmitSetSerializationCred(false),
	_dwSetSerializationCred(CREDENTIAL_PROVIDER_NO_DEFAULT)
{
	DllAddRef();

	ZeroMemory(_rgpCredentials, sizeof(_rgpCredentials));

	log.OpenFile("RdpCredentialProvider.txt", true);
}

RdpProvider::~RdpProvider()
{
	for (size_t i = 0; i < _dwNumCreds; i++)
	{
		if (_rgpCredentials[i] != NULL)
		{
			_rgpCredentials[i]->Release();
		}
	}

	log.CloseFile();

	DllRelease();
}

void RdpProvider::_CleanupSetSerialization()
{
	if (_pkiulSetSerialization)
	{
		KERB_INTERACTIVE_LOGON* pkil = &_pkiulSetSerialization->Logon;
		SecureZeroMemory(_pkiulSetSerialization,
			sizeof(*_pkiulSetSerialization) +
			pkil->LogonDomainName.MaximumLength +
			pkil->UserName.MaximumLength +
			pkil->Password.MaximumLength);
		HeapFree(GetProcessHeap(),0, _pkiulSetSerialization);
	}
}

HRESULT RdpProvider::SetUsageScenario(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, DWORD dwFlags)
{
	UNREFERENCED_PARAMETER(dwFlags);
	HRESULT hr;

	log.Write("RdpProvider::SetUsageScenario: %d dwFlags: 0x%04X", (int) cpus, (int) dwFlags);

	static bool s_bCredsEnumerated = false;

#ifdef RDPCREDPROV_RESTRICTED
	if (cpus == CPUS_CREDUI)
		return E_NOTIMPL;
#endif

	switch (cpus)
	{
		case CPUS_LOGON:
		case CPUS_UNLOCK_WORKSTATION:
		case CPUS_CREDUI:
			if (!s_bCredsEnumerated)
			{
				_cpus = cpus;
				hr = this->_EnumerateCredentials();
				s_bCredsEnumerated = true;
			}
			else
			{
				hr = S_OK;
			}
			break;

		case CPUS_CHANGE_PASSWORD:
			hr = E_NOTIMPL;
			break;

		default:
			hr = E_INVALIDARG;
			break;
	}

	return hr;
}

STDMETHODIMP RdpProvider::SetSerialization(const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs)
{
	HRESULT hr = E_INVALIDARG;

	log.Write("RdpProvider::SetSerialization");

	if ((CLSID_RdpProvider == pcpcs->clsidCredentialProvider))
	{
		ULONG ulAuthPackage;
		hr = RetrieveNegotiateAuthPackage(&ulAuthPackage);

		if (SUCCEEDED(hr))
		{
			if ((ulAuthPackage == pcpcs->ulAuthenticationPackage) && (0 < pcpcs->cbSerialization && pcpcs->rgbSerialization))
			{
				KERB_INTERACTIVE_UNLOCK_LOGON* pkil = (KERB_INTERACTIVE_UNLOCK_LOGON*) pcpcs->rgbSerialization;

				if (KerbInteractiveLogon == pkil->Logon.MessageType)
				{
					BYTE* rgbSerialization;
					rgbSerialization = (BYTE*) HeapAlloc(GetProcessHeap(), 0, pcpcs->cbSerialization);
					hr = rgbSerialization ? S_OK : E_OUTOFMEMORY;

					if (SUCCEEDED(hr))
					{
						CopyMemory(rgbSerialization, pcpcs->rgbSerialization, pcpcs->cbSerialization);
						KerbInteractiveUnlockLogonUnpackInPlace((KERB_INTERACTIVE_UNLOCK_LOGON*) rgbSerialization);

						if (_pkiulSetSerialization)
						{
							HeapFree(GetProcessHeap(), 0, _pkiulSetSerialization);

							if ((_dwSetSerializationCred != CREDENTIAL_PROVIDER_NO_DEFAULT) && (_dwSetSerializationCred == _dwNumCreds - 1))
							{
								_rgpCredentials[_dwSetSerializationCred]->Release();
								_rgpCredentials[_dwSetSerializationCred] = NULL;
								_dwNumCreds--;
								_dwSetSerializationCred = CREDENTIAL_PROVIDER_NO_DEFAULT;
							}
						}

						_pkiulSetSerialization = (KERB_INTERACTIVE_UNLOCK_LOGON*) rgbSerialization;

						hr = S_OK;
					}
				}
			}
		}
		else
		{
			hr = E_INVALIDARG;
		}
	}

	return hr;
}

HRESULT RdpProvider::Advise(ICredentialProviderEvents* pcpe, UINT_PTR upAdviseContext)
{
	UNREFERENCED_PARAMETER(pcpe);
	UNREFERENCED_PARAMETER(upAdviseContext);

	log.Write("RdpProvider::Advise");

	return E_NOTIMPL;
}

HRESULT RdpProvider::UnAdvise()
{
	log.Write("RdpProvider::UnAdvise");

	return E_NOTIMPL;
}

HRESULT RdpProvider::GetFieldDescriptorCount(DWORD* pdwCount)
{
	*pdwCount = SFI_NUM_FIELDS;

	log.Write("RdpProvider::GetFieldDescriptorCount");

	return S_OK;
}

HRESULT RdpProvider::GetFieldDescriptorAt(DWORD dwIndex, CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** ppcpfd)
{    
	HRESULT hr;

	log.Write("RdpProvider::GetFieldDescriptorAt: dwIndex: %d", (int) dwIndex);

	if ((dwIndex < SFI_NUM_FIELDS) && ppcpfd)
	{
		hr = FieldDescriptorCoAllocCopy(s_rgCredProvFieldDescriptors[dwIndex], ppcpfd);
	}
	else
	{ 
		hr = E_INVALIDARG;
	}

	return hr;
}

HRESULT RdpProvider::GetCredentialCount(DWORD* pdwCount, DWORD* pdwDefault, BOOL* pbAutoLogonWithDefault)
{
	HRESULT hr = S_OK;

	log.Write("RdpProvider::GetCredentialCount");

	*pdwCount = 1;
	*pdwDefault = 0;
	
	*pbAutoLogonWithDefault = FALSE;
	//*pbAutoLogonWithDefault = TRUE;

	return hr;
}

HRESULT RdpProvider::GetCredentialAt(DWORD dwIndex, ICredentialProviderCredential** ppcpc)
{
	HRESULT hr;

	log.Write("RdpProvider::GetCredentialAt: dwIndex: %d", (int) dwIndex);

	if ((dwIndex < _dwNumCreds) && ppcpc)
	{
		hr = _rgpCredentials[dwIndex]->QueryInterface(IID_ICredentialProviderCredential, reinterpret_cast<void**>(ppcpc));
	}
	else
	{
		hr = E_INVALIDARG;
	}

	return hr;
}

HRESULT RdpProvider::_EnumerateCredentials()
{
	HRESULT hr;
	DWORD dwCredentialIndex = 0;

	log.Write("RdpProvider::_EnumerateCredentials");

	RdpCredential* ppc = new RdpCredential();

	if (ppc)
	{
		hr = ppc->Initialize(_cpus, s_rgCredProvFieldDescriptors, s_rgFieldStatePairs, L"", NULL, NULL);

		if (SUCCEEDED(hr))
		{
			_rgpCredentials[dwCredentialIndex] = ppc;
			_dwNumCreds++;
		}
		else
		{
			ppc->Release();
		}
	}
	else
	{
		hr = E_OUTOFMEMORY;
	}

	return hr;
}

HRESULT RdpProvider_CreateInstance(REFIID riid, void** ppv)
{
	HRESULT hr;

	RdpProvider* pProvider = new RdpProvider();

	if (pProvider)
	{
		hr = pProvider->QueryInterface(riid, ppv);
		pProvider->Release();
	}
	else
	{
		hr = E_OUTOFMEMORY;
	}

	return hr;
}

HRESULT RdpProvider::_EnumerateSetSerialization()
{
	KERB_INTERACTIVE_LOGON* pkil = &_pkiulSetSerialization->Logon;

	log.Write("RdpProvider::_EnumerateSetSerialization");

	_bAutoSubmitSetSerializationCred = false;

	WCHAR wszUsername[MAX_PATH] = { 0 };
	WCHAR wszPassword[MAX_PATH] = { 0 };

	HRESULT hr = StringCbCopyNW(wszUsername, sizeof(wszUsername), pkil->UserName.Buffer, pkil->UserName.Length);

	if (SUCCEEDED(hr))
	{
		hr = StringCbCopyNW(wszPassword, sizeof(wszPassword), pkil->Password.Buffer, pkil->Password.Length);

		if (SUCCEEDED(hr))
		{
			RdpCredential* pCred = new RdpCredential();

			if (pCred)
			{
				hr = pCred->Initialize(_cpus, s_rgCredProvFieldDescriptors, s_rgFieldStatePairs, wszUsername, wszPassword);

				if (SUCCEEDED(hr))
				{
					_rgpCredentials[_dwNumCreds] = pCred;
					_dwSetSerializationCred = _dwNumCreds;
					_dwNumCreds++;
				}
			}
			else
			{
				hr = E_OUTOFMEMORY;
			}

			if (SUCCEEDED(hr) && (0 < wcslen(wszPassword)))
			{
				_bAutoSubmitSetSerializationCred = true;
			}
		}
	}

	return hr;
}

