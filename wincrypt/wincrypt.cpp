//-------------------------------------------------------------------
// Copyright (C) Microsoft.  All rights reserved.
// Example of encrypting data and creating an enveloped 
// message using CryptEncryptMessage.

#include <stdio.h>
#include <windows.h>
#include <Wincrypt.h>
#include <time.h>


#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "wsock32.lib")

#define AES256_BLOCKSIZE 16
#define ENC_FLAG_NONE   0x0
#define ENC_FLAG_AES256 0x1

typedef struct _Aes256Key
{
	BLOBHEADER header;
	DWORD length;
	BYTE key[256 / 8];
} Aes256Key;

typedef struct _PacketEncryptionContext
{
	HCRYPTPROV provider;
	HCRYPTKEY aes_key;
	int provider_idx;
	BOOL valid;
	Aes256Key key_data;
	BOOL enabled;
} PacketEncryptionContext;



typedef struct _CryptProviderParams
{
	const TCHAR* provider;
	const DWORD type;
	const DWORD flags;
} CryptProviderParams;

typedef struct _RsaKey
{
	BLOBHEADER header;
	DWORD length;
	BYTE key[1];
} RsaKey;


const CryptProviderParams AesProviders[] =
{
	{MS_ENH_RSA_AES_PROV, PROV_RSA_AES, 0},
	{MS_ENH_RSA_AES_PROV, PROV_RSA_AES, CRYPT_NEWKEYSET},
	{MS_ENH_RSA_AES_PROV_XP, PROV_RSA_AES, 0},
	{MS_ENH_RSA_AES_PROV_XP, PROV_RSA_AES, CRYPT_NEWKEYSET}
};


typedef struct
{
	BYTE xor_key[4];
	BYTE session_guid[sizeof(GUID)];
	DWORD enc_flags;
	DWORD length;
	DWORD type;
} PacketHeader;
typedef struct _LOCK
{
	HANDLE handle;
} LOCK, * LPLOCK;
typedef struct _NODE
{
	struct _NODE* next;  ///< Pointer to the next node in the list.
	struct _NODE* prev;  ///< Pointer to the previous node in the list.
	LPVOID data;          ///< Reference to the data in the list node.
} NODE, * PNODE;

/*! @brief Container structure for a list instance. */
typedef struct _LIST
{
	NODE* start;   ///< Pointer to the first node in the list.
	NODE* end;     ///< Pointer to the last node in the list.
	DWORD count;    ///< Count of elements in the list.
	LOCK* lock;    ///< Reference to the list's synchronisation lock.
} LIST, * PLIST;
typedef struct _Packet
{
	PacketHeader header;

	PUCHAR    payload;
	ULONG     payloadLength;

	LIST* decompressed_buffers;

	///！ @brief标志，指示此数据包是否是本地（即不可传输）数据包。
	BOOL local;
	///！ @brief指向关联数据包的指针（响应/请求）
	struct _Packet* partner;
} Packet;

VOID rand_xor_key(BYTE buffer[4])
{
	static BOOL initialised = FALSE;
	if (!initialised)
	{
		srand((unsigned int)time(NULL));
		initialised = TRUE;
	}

	buffer[0] = (rand() % 254) + 1;
	buffer[1] = (rand() % 254) + 1;
	buffer[2] = (rand() % 254) + 1;
	buffer[3] = (rand() % 254) + 1;
}

VOID xor_bytes(BYTE xorKey[4], LPBYTE buffer, DWORD bufferSize)
{
	printf("[XOR] XORing %u bytes with key %02x%02x%02x%02x\n", bufferSize, xorKey[0], xorKey[1], xorKey[2], xorKey[3]);
	for (DWORD i = 0; i < bufferSize; ++i)
	{
		buffer[i] ^= xorKey[i % 4];
	}
}


BYTE session_guid[sizeof(GUID)] = { 0x8B, 0xA6, 0xCF, 0xD7, 0x6B, 0x19, 0x7B , 0xFF , 0xA9 , 0x7B , 0xA8 , 0x79 , 0xFD , 0xDF , 0x27 , 0x1F};  

typedef struct
{
	DWORD length;
	DWORD type;
} TlvHeader;

DWORD My_decrypt_packet(PacketEncryptionContext* enc_ctx, Packet** packet, LPBYTE buffer, DWORD bufferSize)
{
	DWORD result = ERROR_SUCCESS;
	Packet* localPacket = NULL;
	HCRYPTKEY dupKey = 0;


	PUCHAR h = buffer;
	printf("[DEC] Packet header: [0x%02X 0x%02X 0x%02X 0x%02X] [0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X] [0x%02X 0x%02X 0x%02X 0x%02X] [0x%02X 0x%02X 0x%02X 0x%02X] [0x%02X 0x%02X 0x%02X 0x%02X]\n",
		h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7], h[8], h[9], h[10], h[11], h[12], h[13], h[14], h[15], h[16], h[17], h[18], h[19], h[20], h[21], h[22], h[23], h[24], h[25], h[26], h[27], h[28], h[29], h[30], h[31]);


	printf("[DEC] Packet buffer size is: %u\n", bufferSize);

	do
	{
		PacketHeader* header = (PacketHeader*)buffer;

		// Start by decoding the entire packet
		xor_bytes(header->xor_key, buffer + sizeof(header->xor_key), bufferSize - sizeof(header->xor_key));


		h = buffer;
		printf("[DEC] Packet header: [0x%02X 0x%02X 0x%02X 0x%02X] [0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X] [0x%02X 0x%02X 0x%02X 0x%02X] [0x%02X 0x%02X 0x%02X 0x%02X] [0x%02X 0x%02X 0x%02X 0x%02X]\n",
			h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7], h[8], h[9], h[10], h[11], h[12], h[13], h[14], h[15], h[16], h[17], h[18], h[19], h[20], h[21], h[22], h[23], h[24], h[25], h[26], h[27], h[28], h[29], h[30], h[31]);



		// Allocate a packet structure
		if (!(localPacket = (Packet*)calloc(1, sizeof(Packet))))
		{
			result = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}

		DWORD encFlags = ntohl(header->enc_flags);
		printf("[DEC] Encryption flags set to %x\n", encFlags);

		// Only decrypt if the context was set up correctly
		if (enc_ctx != NULL && enc_ctx->valid && encFlags != ENC_FLAG_NONE)
		{
			printf("[DEC] Context is valid, moving on ... \n");
			LPBYTE payload = buffer + sizeof(PacketHeader);

			// the first 16 bytes of the payload we're given is the IV
			LPBYTE iv = payload;

			printf("[DEC] IV: %02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X\n",
				iv[0], iv[1], iv[2], iv[3], iv[4], iv[5], iv[6], iv[7], iv[8], iv[9], iv[10], iv[11], iv[12], iv[13], iv[14], iv[15]);

			// the rest of the payload bytes contains the actual encrypted data
			DWORD encryptedSize = ntohl(header->length) - sizeof(TlvHeader) - AES256_BLOCKSIZE;
			LPBYTE encryptedData = payload + AES256_BLOCKSIZE;

			printf("[DEC] Encrypted Size: %u (%x)\n", encryptedSize, encryptedSize);
			printf("[DEC] Encrypted Size mod AES256_BLOCKSIZE: %u\n", encryptedSize % AES256_BLOCKSIZE);

			if (!CryptDuplicateKey(enc_ctx->aes_key, NULL, 0, &dupKey))
			{
				result = GetLastError();
				printf("[DEC] Failed to duplicate key: %d (%x)\n", result, result);
				break;
			}

			DWORD mode = CRYPT_MODE_CBC;
			if (!CryptSetKeyParam(dupKey, KP_MODE, (const BYTE*)&mode, 0))
			{
				result = GetLastError();
				printf("[ENC] Failed to set mode to CBC: %d (%x)\n", result, result);
				break;
			}

			// decrypt!
			if (!CryptSetKeyParam(dupKey, KP_IV, iv, 0))
			{
				result = GetLastError();
				printf("[DEC] Failed to set IV: %d (%x)\n", result, result);
				break;
			}

			if (!CryptDecrypt(dupKey, 0, TRUE, 0, encryptedData, &encryptedSize))
			{
				result = GetLastError();
				printf("[DEC] Failed to decrypt: %d (%x)\n", result, result);
				break;
			}

			// shift the decrypted data back to the start of the packet buffer so that we
			// can pretend it's a normal packet
			memmove_s(iv, encryptedSize, encryptedData, encryptedSize);

			// adjust the header size
			header->length = htonl(encryptedSize + sizeof(TlvHeader));

			// done, the packet parsing can continue as normal now
		}

		localPacket->header.length = header->length;
		localPacket->header.type = header->type;
		localPacket->payloadLength = ntohl(localPacket->header.length) - sizeof(TlvHeader);

		printf("[DEC] Actual payload Length: %d\n", localPacket->payloadLength);
		printf("[DEC] Header Type: %d\n", ntohl(localPacket->header.type));

		localPacket->payload = (PUCHAR)malloc(localPacket->payloadLength);
		if (localPacket->payload == NULL)
		{
			printf("[DEC] failed to allocate payload\n");
			result = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}

		printf("[DEC] Local packet payload successfully allocated, copying data\n");
		memcpy_s(localPacket->payload, localPacket->payloadLength, buffer + sizeof(PacketHeader), localPacket->payloadLength);

		/*
		h = localPacket->payload;
		printf("[DEC] TLV 1 length / type: [0x%02X 0x%02X 0x%02X 0x%02X] [0x%02X 0x%02X 0x%02X 0x%02X]\n",
			h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
		DWORD tl = ntohl(((TlvHeader*)h)->length);
		printf("[DEC] Skipping %u bytes\n", tl);
		h += tl;
		printf("[DEC] TLV 2 length / type: [0x%02X 0x%02X 0x%02X 0x%02X] [0x%02X 0x%02X 0x%02X 0x%02X]\n",
			h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
		*/

		printf("[DEC] Writing localpacket %p to packet pointer %p\n", localPacket, packet);
		*packet = localPacket;
	} while (0);

	if (result != ERROR_SUCCESS)
	{
		if (localPacket != NULL)
		{
			//packet_destroy(localPacket);
		}
	}
	if (dupKey != 0)
	{
		CryptDestroyKey(dupKey);
	}

	return result;
}
DWORD My_encrypt_packet(PacketEncryptionContext* enc_ctx, Packet* packet, LPBYTE* buffer, LPDWORD bufferSize)
{
	DWORD result = ERROR_SUCCESS;
	HCRYPTKEY dupKey = 0;

	printf("[ENC] Preparing for encryption ...\n");
	// create a new XOR key here, because the content will be copied into the final
	// payload as part of the prepration process
	rand_xor_key(packet->header.xor_key);

	// copy the session ID to the header as this will be used later to identify the packet's destination session
	memcpy_s(packet->header.session_guid, sizeof(packet->header.session_guid), session_guid, sizeof(session_guid));


	// Only encrypt if the context was set up correctly
	if (enc_ctx != NULL && enc_ctx->valid)
	{
		printf("[ENC] Context is valid, moving on ... \n");
		// only encrypt the packet if encryption has been enabled
		if (enc_ctx->enabled)
		{
			do
			{
				printf("[ENC] Context is enabled, doing the AES encryption\n");

				if (!CryptDuplicateKey(enc_ctx->aes_key, NULL, 0, &dupKey))
				{
					result = GetLastError();
					printf("[ENC] Failed to duplicate AES key: %d (%x)\n", result, result);
					break;
				}

				DWORD mode = CRYPT_MODE_CBC;
				if (!CryptSetKeyParam(dupKey, KP_MODE, (const BYTE*)&mode, 0))
				{
					result = GetLastError();
					printf("[ENC] Failed to set mode to CBC: %d (%x)\n", result, result);
					break;
				}

				BYTE iv[AES256_BLOCKSIZE];
				if (!CryptGenRandom(enc_ctx->provider, sizeof(iv), iv))
				{
					result = GetLastError();
					printf("[ENC] Failed to generate random IV: %d (%x)\n", result, result);
				}

				printf("[ENC] IV: %02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X\n",
					iv[0], iv[1], iv[2], iv[3], iv[4], iv[5], iv[6], iv[7], iv[8], iv[9], iv[10], iv[11], iv[12], iv[13], iv[14], iv[15]);


				if (!CryptSetKeyParam(dupKey, KP_IV, iv, 0))
				{
					result = GetLastError();
					printf("[ENC] Failed to set IV: %d (%x)\n", result, result);
					break;
				}

				printf("[ENC] IV Set successfully\n");
				// mark this packet as an encrypted packet
				packet->header.enc_flags = htonl(ENC_FLAG_AES256);


				// Round up
				DWORD maxEncryptSize = ((packet->payloadLength / AES256_BLOCKSIZE) + 1) * AES256_BLOCKSIZE;
				// Need to have space for the IV at the start, as well as the packet Header
				DWORD memSize = maxEncryptSize + sizeof(iv) + sizeof(packet->header);

				*buffer = (BYTE*)malloc(memSize);
				BYTE* headerPos = *buffer;
				BYTE* ivPos = headerPos + sizeof(packet->header);
				BYTE* payloadPos = ivPos + sizeof(iv);

				*bufferSize = packet->payloadLength;

				// prepare the payload
				memcpy_s(payloadPos, packet->payloadLength, packet->payload, packet->payloadLength);

				if (!CryptEncrypt(dupKey, 0, TRUE, 0, payloadPos, bufferSize, maxEncryptSize))
				{
					result = GetLastError();
					printf("[ENC] Failed to encrypt: %d (%x)\n", result, result);
				}
				else
				{
					printf("[ENC] Data encrypted successfully, size is %u\n", *bufferSize);
				}

				// update the length to match the size of the encrypted data with IV and the TlVHeader
				packet->header.length = ntohl(*bufferSize + sizeof(iv) + sizeof(TlvHeader));

				// update the returned total size to include both the IV and header size.
				*bufferSize += sizeof(iv) + sizeof(packet->header);

				// write the header and IV to the payload
				memcpy_s(headerPos, sizeof(packet->header), &packet->header, sizeof(packet->header));
				memcpy_s(ivPos, sizeof(iv), iv, sizeof(iv));
			} while (0);
		}
		else
		{
			printf("[ENC] Enabling the context\n");
			// if the encryption is valid, then we set the enbaled flag here because
			// we know that the first packet going out is the response to the negotiation
			// and from here we want to make sure that the encryption function is on.
			enc_ctx->enabled = TRUE;
		}
	}
	else
	{
		printf("[ENC] No encryption context present\n");
	}

	// if we don't have a valid buffer at this point, we'll create one and add the packet as per normal
	if (*buffer == NULL)
	{
		*bufferSize = packet->payloadLength + sizeof(packet->header);
		*buffer = (BYTE*)malloc(*bufferSize);

		BYTE* headerPos = *buffer;
		BYTE* payloadPos = headerPos + sizeof(packet->header);

		// mark this packet as a non-encrypted packet
		packet->header.enc_flags = htonl(ENC_FLAG_NONE);

		memcpy_s(headerPos, sizeof(packet->header), &packet->header, sizeof(packet->header));
		memcpy_s(payloadPos, packet->payloadLength, packet->payload, packet->payloadLength);
	}
	printf("[ENC] Packet buffer size is: %u\n", *bufferSize);


	LPBYTE h = *buffer;
	printf("[ENC] Sending header (before XOR): [0x%02X 0x%02X 0x%02X 0x%02X] [0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X] [0x%02X 0x%02X 0x%02X 0x%02X] [0x%02X 0x%02X 0x%02X 0x%02X] [0x%02X 0x%02X 0x%02X 0x%02X]\n",
		h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7], h[8], h[9], h[10], h[11], h[12], h[13], h[14], h[15], h[16], h[17], h[18], h[19], h[20], h[21], h[22], h[23], h[24], h[25], h[26], h[27], h[28], h[29], h[30], h[31]);

	// finally XOR obfuscate like we always did before, skippig the xor key itself.
	xor_bytes(packet->header.xor_key, *buffer + sizeof(packet->header.xor_key), *bufferSize - sizeof(packet->header.xor_key));

	printf("[ENC] Packet encoded and ready for transmission\n");

	printf("[ENC] Sending header (after XOR): [0x%02X 0x%02X 0x%02X 0x%02X] [0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X 0x%02X] [0x%02X 0x%02X 0x%02X 0x%02X] [0x%02X 0x%02X 0x%02X 0x%02X] [0x%02X 0x%02X 0x%02X 0x%02X]\n",
		h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7], h[8], h[9], h[10], h[11], h[12], h[13], h[14], h[15], h[16], h[17], h[18], h[19], h[20], h[21], h[22], h[23], h[24], h[25], h[26], h[27], h[28], h[29], h[30], h[31]);


	if (dupKey != 0)
	{
		CryptDestroyKey(dupKey);
	}

	return result;
}

DWORD public_key_encrypt(CHAR* publicKeyPem, unsigned char* data, DWORD dataLength, unsigned char** encryptedData, DWORD* encryptedDataLength)
{
	DWORD result = ERROR_SUCCESS;
	LPBYTE pubKeyBin = NULL;
	CERT_PUBLIC_KEY_INFO* pubKeyInfo = NULL;
	HCRYPTPROV rsaProv = 0;
	HCRYPTKEY pubCryptKey = 0;
	LPBYTE cipherText = NULL;

	do
	{
		if (publicKeyPem == NULL)
		{
			result = ERROR_BAD_ARGUMENTS;
			break;
		}

		DWORD binaryRequiredSize = 0;
		CryptStringToBinaryA(publicKeyPem, 0, CRYPT_STRING_BASE64HEADER, NULL, &binaryRequiredSize, NULL, NULL);
		printf("[ENC] Required size for the binary key is: %u (%x)\n", binaryRequiredSize, binaryRequiredSize);

		pubKeyBin = (LPBYTE)malloc(binaryRequiredSize);
		if (pubKeyBin == NULL)
		{
			result = ERROR_OUTOFMEMORY;
			break;
		}

		if (!CryptStringToBinaryA(publicKeyPem, 0, CRYPT_STRING_BASE64HEADER, pubKeyBin, &binaryRequiredSize, NULL, NULL))
		{
			result = GetLastError();
			printf("[ENC] Failed to convert the given base64 encoded key into bytes: %u (%x)\n", result, result);
			break;
		}

		DWORD keyRequiredSize = 0;
		if (!CryptDecodeObjectEx(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO, pubKeyBin, binaryRequiredSize, CRYPT_ENCODE_ALLOC_FLAG, 0, &pubKeyInfo, &keyRequiredSize))
		{
			result = GetLastError();
			printf("[ENC] Failed to decode: %u (%x)\n", result, result);
			break;
		}

		printf("[ENC] Key algo: %s\n", pubKeyInfo->Algorithm.pszObjId);

		if (!CryptAcquireContext(&rsaProv, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
		{
			printf("[ENC] Failed to create the RSA provider with CRYPT_VERIFYCONTEXT\n");
			if (!CryptAcquireContext(&rsaProv, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, CRYPT_NEWKEYSET))
			{
				result = GetLastError();
				printf("[ENC] Failed to create the RSA provider with CRYPT_NEWKEYSET: %u (%x)\n", result, result);
				break;
			}
			else
			{
				printf("[ENC] Created the RSA provider with CRYPT_NEWKEYSET\n");
			}
		}
		else
		{
			printf("[ENC] Created the RSA provider with CRYPT_VERIFYCONTEXT\n");
		}

		if (!CryptImportPublicKeyInfo(rsaProv, X509_ASN_ENCODING, pubKeyInfo, &pubCryptKey))
		{
			result = GetLastError();
			printf("[ENC] Failed to import the key: %u (%x)\n", result, result);
			break;
		}

		DWORD requiredEncSize = dataLength;
		CryptEncrypt(pubCryptKey, 0, TRUE, 0, NULL, &requiredEncSize, requiredEncSize);
		printf("[ENC] Encrypted data length: %u (%x)\n", requiredEncSize, requiredEncSize);

		cipherText = (LPBYTE)calloc(1, requiredEncSize);
		if (cipherText == NULL)
		{
			result = ERROR_OUTOFMEMORY;
			break;
		}

		memcpy_s(cipherText, requiredEncSize, data, dataLength);

		if (!CryptEncrypt(pubCryptKey, 0, TRUE, 0, cipherText, &dataLength, requiredEncSize))
		{
			result = GetLastError();
			printf("[ENC] Failed to encrypt: %u (%x)\n", result, result);
		}
		else
		{
			printf("[ENC] Encryption witih RSA succeded, byteswapping because MS is stupid and does stuff in little endian.\n");
			// Given that we are encrypting such a small amount of data, we're going to assume that the size
			// of the key matches the size of the block of data we've decrypted.
			for (DWORD i = 0; i < requiredEncSize / 2; ++i)
			{
				BYTE b = cipherText[i];
				cipherText[i] = cipherText[requiredEncSize - i - 1];
				cipherText[requiredEncSize - i - 1] = b;
			}

			*encryptedData = cipherText;
			*encryptedDataLength = requiredEncSize;
		}
	} while (0);

	if (result != ERROR_SUCCESS)
	{
		if (cipherText != NULL)
		{
			free(cipherText);
		}
	}

	if (pubKeyInfo != NULL)
	{
		LocalFree(pubKeyInfo);
	}

	if (pubCryptKey != 0)
	{
		CryptDestroyKey(pubCryptKey);
	}

	if (rsaProv != 0)
	{
		CryptReleaseContext(rsaProv, 0);
	}

	return result;
}


DWORD My_request_negotiate_aes_key(PacketEncryptionContext* enc_ctx)
{
	DWORD result = ERROR_SUCCESS;

	do
	{
		if (enc_ctx != NULL)
		{
			//free enc_ctx
			printf("enc_ctx != NULL\n");
		}

		//enc_ctx = (PacketEncryptionContext*)calloc(1, sizeof(PacketEncryptionContext));

		if (enc_ctx == NULL)
		{
			printf("[ENC] failed to allocate the encryption context\n");
			result = ERROR_OUTOFMEMORY;
			break;
		}

		PacketEncryptionContext* ctx = enc_ctx;

		for (int i = 0; i < _countof(AesProviders); ++i)
		{
			if (!CryptAcquireContext(&ctx->provider, NULL, AesProviders[i].provider, AesProviders[i].type, AesProviders[i].flags))
			{
				result = GetLastError();
				printf("[ENC] failed to acquire the crypt context %d: %d (%x)\n", i, result, result);
			}
			else
			{
				result = ERROR_SUCCESS;
				ctx->provider_idx = i;
				printf("[ENC] managed to acquire the crypt context %d!\n", i);
				break;
			}
		}

		if (result != ERROR_SUCCESS)
		{
			break;
		}

		ctx->key_data.header.bType = PLAINTEXTKEYBLOB;
		ctx->key_data.header.bVersion = CUR_BLOB_VERSION;
		ctx->key_data.header.aiKeyAlg = CALG_AES_256;
		ctx->key_data.length = sizeof(ctx->key_data.key);

		if (!CryptGenRandom(ctx->provider, ctx->key_data.length, ctx->key_data.key))
		{
			result = GetLastError();
			printf("[ENC] failed to generate random key: %d (%x)\n", result, result);
			break;
		}

		if (!CryptImportKey(ctx->provider, (const BYTE*)&ctx->key_data, sizeof(Aes256Key), 0, CRYPT_EXPORTABLE, &ctx->aes_key))
		{
			result = GetLastError();
			printf("[ENC] failed to import random key: %d (%x)\n", result, result);
			break;
		}

		// now we need to encrypt this key data using the public key given

		//get pubKeyPem
		char pubKeyPem[1024];
		FILE* fp = fopen("../Debug/pub.pem", "rb");
		if (fp == NULL)
			return -1;
		fseek(fp, 0, SEEK_SET);
		fread(pubKeyPem, 1024, 1, fp);
		
		printf("%s\n", pubKeyPem);
		unsigned char* cipherText = NULL;
		DWORD cipherTextLength = 0;
		DWORD pubEncryptResult = public_key_encrypt(pubKeyPem, enc_ctx->key_data.key, enc_ctx->key_data.length, &cipherText, &cipherTextLength);


		if (pubEncryptResult == ERROR_SUCCESS && cipherText != NULL)
		{
			printf("密文：%s\n\n", cipherText);
		}
		else
		{
			printf("加密失败\n\n");
		}

		ctx->valid = TRUE;
	} while (0);

	enc_ctx->enabled = TRUE;

	return ERROR_SUCCESS;
}


BOOL My_ExportKey(PacketEncryptionContext* enc_ctx, BYTE* buf)
{
	DWORD pdwDataLen = 0;
	int result = 0;
	result = CryptExportKey(enc_ctx->aes_key, 0, PLAINTEXTKEYBLOB, 0, 0, &pdwDataLen);
	if (!result)
	{
		printf("CryptExportKey导出失败：1 \n\n");
		return FALSE;
	}
	BYTE* pbData = new BYTE[pdwDataLen]{};
	result = CryptExportKey(enc_ctx->aes_key, 0, PLAINTEXTKEYBLOB, 0, pbData, &pdwDataLen);
	if (!result)
	{
		printf("CryptExportKey导出失败：2 \n\n");
		return FALSE;
	}
	memcpy_s(buf, 0x500, pbData, pdwDataLen);
	return TRUE;
}

BOOL GetExportedKey(
	HCRYPTKEY hKey,
	DWORD dwBlobType,
	LPBYTE* ppbKeyBlob,
	LPDWORD pdwBlobLen)
{
	DWORD dwBlobLength;
	*ppbKeyBlob = NULL;
	*pdwBlobLen = 0;

	

	// Export the public key. Here the public key is exported to a 
	// PUBLICKEYBLOB. This BLOB can be written to a file and
	// sent to another user.

	if (CryptExportKey(
		hKey,
		NULL,
		dwBlobType,
		0,
		NULL,
		&dwBlobLength))
	{
		printf("Size of the BLOB for the public key determined. \n");
	}
	else
	{
		int ret = GetLastError();
		printf("Error computing BLOB length.\n");
		return FALSE;
	}

	// Allocate memory for the pbKeyBlob.
	if (*ppbKeyBlob = (LPBYTE)malloc(dwBlobLength))
	{
		printf("Memory has been allocated for the BLOB. \n");
	}
	else
	{
		printf("Out of memory. \n");
		return FALSE;
	}

	// Do the actual exporting into the key BLOB.
	if (CryptExportKey(
		hKey,
		NULL,
		dwBlobType,
		0,
		*ppbKeyBlob,
		&dwBlobLength))
	{
		printf("Contents have been written to the BLOB. \n");
		*pdwBlobLen = dwBlobLength;
	}
	else
	{
		printf("Error exporting key.\n");
		free(*ppbKeyBlob);
		*ppbKeyBlob = NULL;

		return FALSE;
	}

	return TRUE;
}

BOOL wincryptTest()
{
	PacketEncryptionContext* enc_ctx = new PacketEncryptionContext;
	Packet* packet = new Packet;
	Packet* packet_accept = new Packet;
	UCHAR ttt[21] = "aaabbbcccddd";
	packet->payload = ttt;
	packet->payloadLength = 12;
	BYTE* encryptedPacket = NULL;
	DWORD encryptedPacketLength = 0;


	//密钥协商
	My_request_negotiate_aes_key(enc_ctx);
	//加密
	My_encrypt_packet(enc_ctx, packet, &encryptedPacket, &encryptedPacketLength);
	printf("[ENC] Text: %s  \n\n", packet->payload);
	printf("[ENC] Encrypted: %s  \n\n", encryptedPacket);
	//解密
	My_decrypt_packet(enc_ctx, &packet_accept, encryptedPacket, encryptedPacketLength);
	printf("[DEC] Decrypted: %s  \n\n", packet_accept->payload);
	//导出私钥
	BYTE* ppbKeyBlob = new BYTE[0x500]{};
	DWORD pdwBlobLen = 0;
	GetExportedKey(enc_ctx->aes_key, PLAINTEXTKEYBLOB, &ppbKeyBlob, &pdwBlobLen);
	printf("[KEY] ppbKeyBlob:");
	for (int i = 0; i < 44; i++)
	{
		if (i == 8 || i == 12)
		{
			printf(" ");
		}
		printf("%02X", ppbKeyBlob[i]);

	}
	printf("\n\n");
	return TRUE;
}
int main()
{
	//wincryptTest();

	//get PacketStream
	int size = 0;
	BYTE* PacketStream = NULL;
	FILE* fp = fopen("../Debug/PacketStream.bin", "rb");
	if (fp == NULL)
		return -1;
	fseek(fp, 0, SEEK_END);
	size = ftell(fp);
	PacketStream = new BYTE[size+1]{};
	fseek(fp, 0, SEEK_SET);
	fread(PacketStream, size, 1, fp);

	PacketEncryptionContext* enc_ctx = new PacketEncryptionContext;
	Packet* packet = new Packet;
	Packet* packet_accept = new Packet;
	UCHAR ttt[21] = "aaabbbcccddd";
	packet->payload = ttt;
	packet->payloadLength = 12;
	BYTE* encryptedPacket = NULL;
	DWORD encryptedPacketLength = 0;


	//密钥协商
	My_request_negotiate_aes_key(enc_ctx);
	//替换key
	enc_ctx->key_data.key;
	BYTE key[] = {0xFC, 0x13, 0xD3, 0x44, 0x24, 0x8A, 0x5D, 0x17, 0xCF, 0x21, 0x32, 0xF9, 0x5B, 0x98, 0xA3, 0x8F, 0x0A, 
		0x6C, 0x01, 0x3D, 0x02, 0x88, 0x0E, 0xD0, 0xC4, 0x7F, 0x96, 0xF7, 0xA6, 0x21, 0x1D, 0xAC };
	memcpy_s(enc_ctx->key_data.key, 32, key, 32);
	//解密
	My_decrypt_packet(enc_ctx, &packet_accept, PacketStream, size);
	printf("[DEC] Decrypted: %s  \n\n", packet_accept->payload);
	system("pause");

	return 1;
} // End of main


void ByteToStr(
	DWORD cb,
	void* pv,
	LPSTR sz)
	//-------------------------------------------------------------------
	// Parameters passed are:
	//    pv is the array of BYTEs to be converted.
	//    cb is the number of BYTEs in the array.
	//    sz is a pointer to the string to be returned.

{
	//-------------------------------------------------------------------
	//  Declare and initialize local variables.

	BYTE* pb = (BYTE*)pv; // Local pointer to a BYTE in the BYTE array
	DWORD i;               // Local loop counter
	int b;                 // Local variable

	//-------------------------------------------------------------------
	//  Begin processing loop.

	for (i = 0; i < cb; i++)
	{
		b = (*pb & 0xF0) >> 4;
		*sz++ = (b <= 9) ? b + '0' : (b - 10) + 'A';
		b = *pb & 0x0F;
		*sz++ = (b <= 9) ? b + '0' : (b - 10) + 'A';
		pb++;
	}
	*sz++ = 0;
} // End of ByteToStr