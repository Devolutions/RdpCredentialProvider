
#include <credentialprovider.h>
#include "RdpProvider.h"
#include "RdpCredential.h"
#include "guid.h"

RdpProvider::RdpProvider():
	_cRef(1),
	_pkiulSetSerialization(NULL),
	_dwNumCreds(0),
	_bAutoSubmitSetSerializationCred(false),
	_dwSetSerializationCred(CREDENTIAL_PROVIDER_NO_DEFAULT)
{
	DllAddRef();

	ZeroMemory(_rgpCredentials, sizeof(_rgpCredentials));
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

	static bool s_bCredsEnumerated = false;

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

	if ((CLSID_RdpProvider == pcpcs->clsidCredentialProvider))
	{
		ULONG ulAuthPackage;
		hr = RetrieveNegotiateAuthPackage(&ulAuthPackage);

		if (SUCCEEDED(hr))
		{
			if ((ulAuthPackage == pcpcs->ulAuthenticationPackage) &&
				(0 < pcpcs->cbSerialization && pcpcs->rgbSerialization))
			{
				KERB_INTERACTIVE_UNLOCK_LOGON* pkil = (KERB_INTERACTIVE_UNLOCK_LOGON*) pcpcs->rgbSerialization;
				if (KerbInteractiveLogon == pkil->Logon.MessageType)
				{
					BYTE* rgbSerialization;
					rgbSerialization = (BYTE*)HeapAlloc(GetProcessHeap(), 0, pcpcs->cbSerialization);
					hr = rgbSerialization ? S_OK : E_OUTOFMEMORY;

					if (SUCCEEDED(hr))
					{
						CopyMemory(rgbSerialization, pcpcs->rgbSerialization, pcpcs->cbSerialization);
						KerbInteractiveUnlockLogonUnpackInPlace((KERB_INTERACTIVE_UNLOCK_LOGON*)rgbSerialization);

						if (_pkiulSetSerialization)
						{
							HeapFree(GetProcessHeap(), 0, _pkiulSetSerialization);

							if (_dwSetSerializationCred != CREDENTIAL_PROVIDER_NO_DEFAULT && _dwSetSerializationCred == _dwNumCreds - 1)
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

	return E_NOTIMPL;
}

HRESULT RdpProvider::UnAdvise()
{
	return E_NOTIMPL;
}

HRESULT RdpProvider::GetFieldDescriptorCount(DWORD* pdwCount)
{
	*pdwCount = SFI_NUM_FIELDS;

	return S_OK;
}

HRESULT RdpProvider::GetFieldDescriptorAt(DWORD dwIndex, CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** ppcpfd)
{    
	HRESULT hr;

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

	if (_pkiulSetSerialization && _dwSetSerializationCred == CREDENTIAL_PROVIDER_NO_DEFAULT)
	{
		_EnumerateSetSerialization();
	}

	*pdwCount = _dwNumCreds;

	if (*pdwCount > 0)
	{
		if (_dwSetSerializationCred != CREDENTIAL_PROVIDER_NO_DEFAULT)
		{
			*pdwDefault = _dwSetSerializationCred;
		}
		else
		{
			*pdwDefault = CREDENTIAL_PROVIDER_NO_DEFAULT;
		}

		*pbAutoLogonWithDefault = _bAutoSubmitSetSerializationCred;
	}
	else
	{
		*pdwDefault = CREDENTIAL_PROVIDER_NO_DEFAULT;
		*pbAutoLogonWithDefault = FALSE;
		hr = E_FAIL;
	}

	return hr;
}

HRESULT RdpProvider::GetCredentialAt(DWORD dwIndex, ICredentialProviderCredential** ppcpc)
{
	HRESULT hr;

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

HRESULT RdpProvider::_EnumerateOneCredential(DWORD dwCredentialIndex, PCWSTR pwzUsername)
{
	HRESULT hr;

	RdpCredential* ppc = new RdpCredential();

	if (ppc)
	{
		hr = ppc->Initialize(_cpus, s_rgCredProvFieldDescriptors, s_rgFieldStatePairs, pwzUsername);

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

HRESULT RdpProvider::_EnumerateCredentials()
{
	HRESULT hr = _EnumerateOneCredential(0, L"Administrator");

	if (SUCCEEDED(hr))
	{
		hr = _EnumerateOneCredential(1, L"Guest");
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

	_bAutoSubmitSetSerializationCred = false;

	WCHAR wszUsername[MAX_PATH] = {0};
	WCHAR wszPassword[MAX_PATH] = {0};

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

