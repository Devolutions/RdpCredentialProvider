
#pragma once
#include <credentialprovider.h>
#include <ntsecapi.h>
#define SECURITY_WIN32
#include <security.h>
#include <intsafe.h>

#define MAX_ULONG  ((ULONG)(-1))

enum SAMPLE_FIELD_ID 
{
	SFI_TILEIMAGE       = 0,
	SFI_USERNAME        = 1,
	SFI_PASSWORD        = 2,
	SFI_SUBMIT_BUTTON   = 3,
	SFI_NUM_FIELDS      = 4,
};

struct FIELD_STATE_PAIR
{
	CREDENTIAL_PROVIDER_FIELD_STATE cpfs;
	CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE cpfis;
};

static const FIELD_STATE_PAIR s_rgFieldStatePairs[] = 
{
	{ CPFS_DISPLAY_IN_BOTH, CPFIS_NONE },
	{ CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE },
	{ CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_FOCUSED },
	{ CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE },
};

static const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR s_rgCredProvFieldDescriptors[] =
{
	{ SFI_TILEIMAGE, CPFT_TILE_IMAGE, L"Image" },
	{ SFI_USERNAME, CPFT_EDIT_TEXT, L"User name" },
	{ SFI_PASSWORD, CPFT_PASSWORD_TEXT, L"Password" },
	{ SFI_SUBMIT_BUTTON, CPFT_SUBMIT_BUTTON, L"Submit" },
};