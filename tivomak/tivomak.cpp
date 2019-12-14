// tivomak.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "tivomak.h"
#include "CmdLine.h"
#include "hasher.h"

#pragma comment(lib, "Crypt32")

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

namespace
{
	static const BYTE globalcurrententropy[] = {0x7B, 0x42, 0x30, 0x41, 0x37, 0x39,
		0x36, 0x31, 0x33, 0x2D, 0x44, 0x32,
		0x32, 0x32, 0x2D, 0x34, 0x37, 0x44,
		0x30, 0x2D, 0x38, 0x39, 0x41, 0x43,
		0x2D, 0x37, 0x31, 0x30, 0x42, 0x31,
		0x44, 0x41, 0x44, 0x34, 0x43, 0x46,
		0x36, 0x7D};

	static const ULONG currententropysize        = 0x32;
	static const DATA_BLOB tivo_legacy_entropy = {1, (BYTE*)""};
	static LPCTSTR TIVO_SHARINGKEYS_REGKEY    = _T("SOFTWARE\\TiVo\\SharingKeys");
	static LPCTSTR TIVO_MEDIAKEY_REGVALUE     = _T("TiVoToGo Media");
	static LPCTSTR TIVO_METAKEY_REGVALUE      = _T("TiVoToGo Metadata");
	static LPCSTR  TIVO_MEDIAKEY_PREFIX       = "tivo:";
	static LPCSTR  TIVO_METAKEY_PREFIX        = "tivo:TiVo DVR:";
	static LPCWSTR TIVO_PROTECT_DESCR         = L"TiVo Sharing Key";

	static HRESULT get_current_entropy (BYTE* current_entropy)
	{
		TCHAR windir[MAX_PATH];
		WIN32_FIND_DATA FindFileInfo;
		HANDLE findfilehandle;
		DWORD vol_serial_num;
		LPTSTR root;
		BYTE* buffer = current_entropy + 38;

		memcpy(current_entropy, globalcurrententropy, sizeof(globalcurrententropy));

		if (!GetWindowsDirectory(windir, MAX_PATH))
			return AtlHresultFromLastError();

		memset(&FindFileInfo, 0, sizeof(FindFileInfo));

		if ((findfilehandle = FindFirstFile(windir, &FindFileInfo)) == INVALID_HANDLE_VALUE)
			return AtlHresultFromLastError();

		FindClose(findfilehandle);

		memcpy(buffer,   &FindFileInfo.ftCreationTime.dwLowDateTime, 4);
		memcpy(buffer+4, &FindFileInfo.ftCreationTime.dwHighDateTime, 4);

		if ((root = _tcschr(windir, 0x5C)))
		{
			*(++root) = '\0';
		}

		if (!GetVolumeInformation(windir, NULL, 0, &vol_serial_num, NULL, NULL, NULL, 0))
			return AtlHresultFromLastError();

		memcpy(buffer+8, &vol_serial_num, 4);

		*(buffer+12) = '\0';

		return S_OK;
	}

	template <typename FreeFunc>
	class DataBlobRAII : public DATA_BLOB
	{
		FreeFunc m_free;
	public:
		DataBlobRAII(FreeFunc free, DWORD dataLen = 0, BYTE* dataPtr = NULL)
			: m_free (free)
		{
			cbData = dataLen;
			pbData = dataPtr;
		}
		~DataBlobRAII()
		{
			if (pbData)
				m_free(pbData);
		}
	};

} // end anonymous namespace


CString GetMAK()
{
	DATA_BLOB crypted_data;
	DATA_BLOB uncrypted_data;

	CRegKey reg;
	if (ERROR_SUCCESS == reg.Open(HKEY_CURRENT_USER, TIVO_SHARINGKEYS_REGKEY, KEY_READ)) 
	{
		if (ERROR_SUCCESS == reg.QueryBinaryValue(TIVO_MEDIAKEY_REGVALUE, NULL, &crypted_data.cbData))
		{
			crypted_data.pbData = (BYTE*)malloc(crypted_data.cbData);
			if (crypted_data.pbData != NULL)
			{
				if (ERROR_SUCCESS == reg.QueryBinaryValue(TIVO_MEDIAKEY_REGVALUE, crypted_data.pbData, &crypted_data.cbData))
				{
					if (CryptUnprotectData(
						&crypted_data,
						NULL,
						const_cast<DATA_BLOB*>(&tivo_legacy_entropy),
						NULL,
						NULL,
						0,
						&uncrypted_data))
					{
						CString szMak(reinterpret_cast< char const* >(uncrypted_data.pbData + 5));
						return szMak;
					}
					else
					{
						BYTE current_entropy [sizeof(globalcurrententropy) + 13];
						DATA_BLOB currententropy = {currententropysize, current_entropy};

						if (S_OK == get_current_entropy(current_entropy))
						{
							if (CryptUnprotectData(
								&crypted_data,
								NULL,
								&currententropy,
								NULL,
								NULL,
								0,
								&uncrypted_data))
							{
								CString szMak(reinterpret_cast< char const* >(uncrypted_data.pbData + 5));
								return szMak;
							}
						}
					}
				}
			}
		}
	}

	return _T("");
}

BOOL SetMAK(CString sMak)
{
	std::string mak = sMak;

	std::string metakey (TIVO_MEDIAKEY_PREFIX);
	std::string mediakey (TIVO_MEDIAKEY_PREFIX);
	std::string md5key;
	std::string metakey_tohash (TIVO_METAKEY_PREFIX);

	BYTE current_entropy [sizeof(globalcurrententropy) + 13];
	DATA_BLOB currententropy = {currententropysize, current_entropy};
	DATA_BLOB media_data_in,  meta_data_in;
	DataBlobRAII<HLOCAL (WINAPI*)(HLOCAL)> media_data_out (LocalFree), meta_data_out(LocalFree);

	mediakey.append(mak);
	metakey_tohash.append(mak);

	CRegKey reg;
	if (ERROR_SUCCESS != reg.Create(HKEY_CURRENT_USER, TIVO_SHARINGKEYS_REGKEY))
		return FALSE;

	if (S_OK != get_current_entropy(current_entropy))
		return FALSE;


	{
		Hasher hasher(CALG_MD5);
		hasher(metakey_tohash);
		hasher.finish (md5key);
	}

	metakey.append(md5key);

	/* +1 for the NUL byte */
	media_data_in.cbData = (DWORD)mediakey.size() + 1;
	media_data_in.pbData = (BYTE*)mediakey.data();

	/* +1 for the NUL byte */
	meta_data_in.cbData = (DWORD)metakey.size() + 1;
	meta_data_in.pbData = (BYTE*)metakey.data();

	if (!CryptProtectData (
		&media_data_in,
		TIVO_PROTECT_DESCR,
		const_cast<DATA_BLOB*> (&tivo_legacy_entropy),
		NULL,
		NULL,
		0,
		&media_data_out))
	{
		return FALSE;
	}

	if (!CryptProtectData (
		&meta_data_in,
		TIVO_PROTECT_DESCR,
		&currententropy,
		NULL,
		NULL,
		0,
		&meta_data_out))
	{
		return FALSE;
	}

	if (ERROR_SUCCESS != reg.SetBinaryValue(TIVO_MEDIAKEY_REGVALUE, media_data_out.pbData, media_data_out.cbData))
		return FALSE;

	if (ERROR_SUCCESS != reg.SetBinaryValue (TIVO_METAKEY_REGVALUE, meta_data_out.pbData, meta_data_out.cbData))
		return FALSE;

	return TRUE;
}


// The one and only application object

CWinApp theApp;

using namespace std;

int main()
{
    int nRetCode = 0;

    HMODULE hModule = ::GetModuleHandle(nullptr);

    if (hModule != nullptr)
    {
        // initialize MFC and print and error on failure
        if (!AfxWinInit(hModule, nullptr, ::GetCommandLine(), 0))
        {
            // TODO: change error code to suit your needs
            printf("Fatal Error: MFC initialization failed\n");
            nRetCode = 1;
        }
        else
        {
			CCmdLine cmdLine;

			// parse the command line.
			if (cmdLine.SplitLine(__argc, __argv) > 0)
			{
				CString szMak = cmdLine.GetArgument("-set", 0);
				if (szMak.GetLength())
				{
					if(szMak.GetLength() == 10)
					{
						if (!SetMAK(szMak))
						{
							printf("Error: Unable to set MAK\n");
							nRetCode = 1;
						}
						else
							printf(GetMAK());

					}
					else
					{
						printf("Error: Invalid MAK length\n");
						nRetCode = 1;
					}

				}
				else
				{
					printf("Error: Invalid MAK length\n");
					nRetCode = 1;
				}
			}
			else
			{
				CString szMak = GetMAK();
				if (szMak.GetLength())
					printf(szMak);
				else
				{
					printf("Error: Unable to get MAK\n");
					nRetCode = 1;
				}
			}
        }
    }
    else
    {
        // TODO: change error code to suit your needs
        wprintf(L"Fatal Error: GetModuleHandle failed\n");
        nRetCode = 1;
    }

    return nRetCode;
}
