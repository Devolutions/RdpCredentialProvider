
#include <credentialprovider.h>
#include <windows.h>
#include <strsafe.h>

#include "RdpCredential.h"
#include "helpers.h"

#define MAX_CREDENTIALS		3
#define MAX_DWORD		0xFFFFFFFF

class RdpProvider : public ICredentialProvider
{
public:
	// IUnknown
	STDMETHOD_(ULONG, AddRef)()
	{
		return _cRef++;
	}

	STDMETHOD_(ULONG, Release)()
	{
		LONG cRef = _cRef--;
		if (!cRef)
		{
			delete this;
		}
		return cRef;
	}

	STDMETHOD (QueryInterface)(REFIID riid, void** ppv)
	{
		HRESULT hr;
		if (IID_IUnknown == riid || 
			IID_ICredentialProvider == riid)
		{
			*ppv = this;
			reinterpret_cast<IUnknown*>(*ppv)->AddRef();
			hr = S_OK;
		}
		else
		{
			*ppv = NULL;
			hr = E_NOINTERFACE;
		}
		return hr;
	}

public:
	IFACEMETHODIMP SetUsageScenario(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, DWORD dwFlags);
	IFACEMETHODIMP SetSerialization(const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs);

	IFACEMETHODIMP Advise(__in ICredentialProviderEvents* pcpe, UINT_PTR upAdviseContext);
	IFACEMETHODIMP UnAdvise();

	IFACEMETHODIMP GetFieldDescriptorCount(__out DWORD* pdwCount);
	IFACEMETHODIMP GetFieldDescriptorAt(DWORD dwIndex,  __deref_out CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** ppcpfd);

	IFACEMETHODIMP GetCredentialCount(__out DWORD* pdwCount,
		__out DWORD* pdwDefault,
		__out BOOL* pbAutoLogonWithDefault);
	IFACEMETHODIMP GetCredentialAt(DWORD dwIndex, 
		__out ICredentialProviderCredential** ppcpc);

	friend HRESULT RdpProvider_CreateInstance(REFIID riid, __deref_out void** ppv);

protected:
	RdpProvider();
	__override ~RdpProvider();

private:

	HRESULT _EnumerateOneCredential(__in DWORD dwCredientialIndex, __in PCWSTR pwzUsername);
	HRESULT _EnumerateSetSerialization();

	HRESULT _EnumerateCredentials();
	void _ReleaseEnumeratedCredentials();
	void _CleanupSetSerialization();

private:
	LONG              _cRef;
	RdpCredential *_rgpCredentials[MAX_CREDENTIALS];
	DWORD                                   _dwNumCreds;
	KERB_INTERACTIVE_UNLOCK_LOGON*          _pkiulSetSerialization;
	DWORD                                   _dwSetSerializationCred;
	bool                                    _bAutoSubmitSetSerializationCred;
	CREDENTIAL_PROVIDER_USAGE_SCENARIO      _cpus;
};
