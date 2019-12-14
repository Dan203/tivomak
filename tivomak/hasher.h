#ifndef HASHER_H__
#define HASHER_H__
#include <wincrypt.h>

class Hasher
{
public:
	Hasher(ALG_ID algId, DWORD provType = PROV_RSA_FULL, LPCTSTR provider = NULL)
		: m_hProv (NULL)
		, m_hHash (NULL)
	{
		if (CryptAcquireContext(&m_hProv, NULL, provider, provType, CRYPT_VERIFYCONTEXT))
		{
			if (!CryptCreateHash(m_hProv, algId, 0, 0, &m_hHash))
			{
				if (m_hProv)
					CryptReleaseContext(m_hProv, 0);
			}
		}
	}

	~Hasher()
	{
		if (m_hHash)
			CryptDestroyHash(m_hHash);

		if (m_hProv)
			CryptReleaseContext(m_hProv, 0);
	}

	inline void operator() (const BYTE* data, DWORD size)
	{
		CryptHashData(m_hHash, data, size, 0);
	}

	inline void operator() (const std::string & str)
	{
		operator() (
			reinterpret_cast<const BYTE *>(str.data()),
			static_cast<DWORD>(str.size())
		);
	}

	DWORD size ()
	{
		DWORD dwRetval, dwSizeofRetval = sizeof(dwRetval);
		if (!CryptGetHashParam(
			m_hHash,
			HP_HASHSIZE,
			reinterpret_cast<BYTE*>(&dwRetval),
			&dwSizeofRetval,
			0))
		{
			dwRetval = 0;
		}
		return dwRetval;
	}

	inline void finish (__out BYTE* output, __inout DWORD * pdwSize)
	{
		CryptGetHashParam(m_hHash, HP_HASHVAL, output, pdwSize, 0);
	}

	inline void finish (__out std::string & hex)
	{
		DWORD hashsize = this->size();
		BYTE* hashout = new BYTE [hashsize];

		finish(hashout, &hashsize);
		hex.resize(hashsize * 2);
		buffer2hexstr(hex, hashout, hashsize);
		delete[] hashout;
	}

private:
	HCRYPTPROV m_hProv;
	HCRYPTHASH m_hHash;

	template<typename String>
	static inline void buffer2hexstr(String& outstr, BYTE * buffer, DWORD bufferlen)
	{
		static const char lookup[] = "0123456789abcdef";

		for(DWORD i = 0; i < bufferlen; ++i)
		{
			outstr[2*i] = lookup[(buffer[i] >> 4) & 0xf];
			outstr[2*i+1] = lookup[buffer[i] & 0xf];
		}
	}
};

#endif // HASHER_H__
