/******************************************************************************
Copyright (C), 2011-2015, Hisilicon Tech. Co., Ltd.
******************************************************************************
File Name     : sample_anticopy.c
Version       : Initial Draft
Author        : Hisilicon
Created       : 2013/09/23
Last Modified :
Description   :	
Function List :
History       :
******************************************************************************/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <linux/fb.h>
#include <assert.h>

#include "hi_type.h"
#include "hi_unf_cipher.h"
#include "hi_mmz_api.h"



#define HI_ERR_CIPHER(format, arg...)    printf( "%s,%d: " format , __FUNCTION__, __LINE__, ## arg)
#define HI_INFO_CIPHER(format, arg...)   printf( "%s,%d: " format , __FUNCTION__, __LINE__, ## arg)

static const HI_U8 g_au8RootKey[16] = {0x46, 0x00, 0x00, 0x00, 0x55, 0x00, 0x00, 0x00, 0x43, 0x00, 0x00, 0x00, 0x4B, 0x00, 0x00, 0x00};
static const HI_U8 g_au8RootKey2[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};


static HI_U8 aes_128_cbc_key[16] = {0x01,0x00,0x00,0x00,0x02,0x00,0x00,0x00,0x03,0x00,0x00,0x00,0x04,0x00,0x00,0x00};
static HI_U8 aes_128_cbc_IV[16]  = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F};
static HI_U8 aes_128_src_buf[16] = {0x6B,0xC1,0xBE,0xE2,0x2E,0x40,0x9F,0x96,0xE9,0x3D,0x7E,0x11,0x73,0x93,0x17,0x2A};
static HI_U8 aes_128_dst_buf[16] = {0xce,0x3e,0x7f,0xb9,0x2b,0xc8,0xc7,0xa3,0xe8,0xd8,0x65,0xd3,0x72,0x49,0x48,0x7c};
//static HI_U8 aes_128_dst_buf2[16] = {0xa0,0xfc,0x76,0x80,0x0e,0x2e,0x05,0x12,0x62,0xf3,0x96,0x86,0xf4,0x6e,0xc4,0xd6};



static HI_S32 printBuffer(const HI_CHAR *string, const HI_U8 *pu8Input, HI_U32 u32Length)
{
    HI_U32 i = 0;
    
    if ( NULL != string )
    {
        printf("%s\n", string);
    }

    for ( i = 0 ; i < u32Length; i++ )
    {
        if( (i % 16 == 0) && (i != 0)) printf("\n");
        printf("0x%02x ", pu8Input[i]);
    }
    printf("\n");

    return HI_SUCCESS;
}

static HI_S32 Sample_Cipher_SetConfig( HI_HANDLE chnHandle,
                                           HI_UNF_CIPHER_KEY_SRC_E enKeySrc,
                                           HI_UNF_CIPHER_ALG_E enAlg,
                                           HI_UNF_CIPHER_WORK_MODE_E enMode,
                                           HI_UNF_CIPHER_KEY_LENGTH_E enKeyLen,
                                           const HI_U8 u8KeyBuf[16],
                                           const HI_U8 u8IVBuf[16] )
{
	HI_S32 s32Ret = HI_SUCCESS;
    HI_UNF_CIPHER_CTRL_S CipherCtrl;
    
    memset(&CipherCtrl, 0, sizeof(HI_UNF_CIPHER_CTRL_S));
    CipherCtrl.enAlg = enAlg;
    CipherCtrl.enWorkMode = enMode;
    CipherCtrl.enBitWidth = HI_UNF_CIPHER_BIT_WIDTH_128BIT;
    CipherCtrl.enKeyLen = enKeyLen;
    CipherCtrl.enKeySrc = enKeySrc;
    if(CipherCtrl.enWorkMode != HI_UNF_CIPHER_WORK_MODE_ECB)
    {
        CipherCtrl.stChangeFlags.bit1IV = 1;  //must set for CBC , CFB mode
        memcpy(CipherCtrl.u32IV, u8IVBuf, 16);
    }

    if ( HI_UNF_CIPHER_KEY_SRC_USER == enKeySrc )
    {
        memcpy(CipherCtrl.u32Key, u8KeyBuf, 32);
    }        

    s32Ret = HI_UNF_CIPHER_ConfigHandle(chnHandle, &CipherCtrl);
    if(HI_SUCCESS != s32Ret)
	{
		return HI_FAILURE;	
	}

    return HI_SUCCESS;
}


HI_S32 main(int argc, char* argv[])
{
	HI_S32 s32Ret = HI_SUCCESS;
    HI_U32 u32TestDataLen = 16;
    HI_U32 u32InputAddrPhy = 0;
    HI_U32 u32OutPutAddrPhy = 0;
    HI_U32 u32Testcached = 0;
    HI_U8 *pInputAddrVir = HI_NULL;
    HI_U8 *pOutputAddrVir = HI_NULL;
    HI_HANDLE hTestchnid = 0;
    HI_U32 u32OtpId = 0;

    /* 1, init cipher */
    s32Ret = HI_UNF_CIPHER_Init();
    if(HI_SUCCESS != s32Ret)
	{
		return HI_FAILURE;	
	}

    /* 2, burn key to OTP */
    s32Ret = HI_UNF_CIPHER_WriteOTPKey(u32OtpId, g_au8RootKey, 16);
    if(HI_SUCCESS != s32Ret)
    {
        return HI_FAILURE;	
    }

    /* 3, create a cipher chn */
    s32Ret = HI_UNF_CIPHER_CreateHandle(&hTestchnid);
    if(HI_SUCCESS != s32Ret)
	{
		HI_UNF_CIPHER_DeInit();
		return HI_FAILURE;	
	}

    u32InputAddrPhy = (HI_U32)HI_MMZ_New(u32TestDataLen, 0, NULL, "CIPHER_BufIn");
    if (0 == u32InputAddrPhy)
    {
        HI_ERR_CIPHER("Error: Get phyaddr for input failed!\n");
        goto __CIPHER_EXIT__;
    }
    pInputAddrVir = HI_MMZ_Map(u32InputAddrPhy, u32Testcached);
    
    u32OutPutAddrPhy = (HI_U32)HI_MMZ_New(u32TestDataLen, 0, NULL, "CIPHER_BufOut");
    if (0 == u32OutPutAddrPhy)
    {
        HI_ERR_CIPHER("Error: Get phyaddr for outPut failed!\n");
        goto __CIPHER_EXIT__;
    }
    pOutputAddrVir = HI_MMZ_Map(u32OutPutAddrPhy, u32Testcached);
    
	/* 4, load otp key to cipher chn for encrypt */
    s32Ret = Sample_Cipher_SetConfig(hTestchnid, 
                            HI_UNF_CIPHER_KEY_SRC_EFUSE_0, 
                            HI_UNF_CIPHER_ALG_AES, 
                            HI_UNF_CIPHER_WORK_MODE_CBC, 
                            HI_UNF_CIPHER_KEY_AES_128BIT,
                            aes_128_cbc_key, 
                            aes_128_cbc_IV);
	if(HI_SUCCESS != s32Ret)
	{
		HI_ERR_CIPHER("Set config info failed.\n");
		goto __CIPHER_EXIT__;	
	}

    memset(pInputAddrVir, 0x0, u32TestDataLen);
    memcpy(pInputAddrVir, aes_128_src_buf, u32TestDataLen);
    printBuffer("clear text:", aes_128_src_buf, sizeof(aes_128_src_buf));

    memset(pOutputAddrVir, 0x0, u32TestDataLen);

    /* 5, use otp key loaded to cipher to encrypt data1-->aes_128_src_buf */ 
    s32Ret = HI_UNF_CIPHER_Encrypt(hTestchnid, u32InputAddrPhy, u32OutPutAddrPhy, u32TestDataLen);
    if(HI_SUCCESS != s32Ret)
	{
		HI_ERR_CIPHER("Cipher encrypt failed.\n");
		s32Ret = HI_FAILURE;
		goto __CIPHER_EXIT__;	
	}
	
    printBuffer("encrypted text:", pOutputAddrVir, sizeof(aes_128_dst_buf));

    /* compare */
    if ( 0 != memcmp(pOutputAddrVir, aes_128_dst_buf, u32TestDataLen) )
    {
        HI_ERR_CIPHER("Memcmp failed!\n");
        s32Ret = HI_FAILURE;
        goto __CIPHER_EXIT__;
    }
    else
    {
        printf("Encrypt : verify ok!\n");
    }

    printf("press any key to decrypt:\n");
    getchar();
    /* For decrypt */
    memcpy(pInputAddrVir, aes_128_dst_buf, u32TestDataLen);
    memset(pOutputAddrVir, 0x0, u32TestDataLen);
    
    /* 6, load otp key to cipher chn for decrypt */
	s32Ret = Sample_Cipher_SetConfig(hTestchnid, 
                                    HI_UNF_CIPHER_KEY_SRC_EFUSE_0, 
                                    HI_UNF_CIPHER_ALG_AES, 
                                    HI_UNF_CIPHER_WORK_MODE_CBC, 
                                    HI_UNF_CIPHER_KEY_AES_128BIT,
                                    aes_128_cbc_key, 
                                    aes_128_cbc_IV);
	if(HI_SUCCESS != s32Ret)
	{
		HI_ERR_CIPHER("Set config info failed.\n");
		goto __CIPHER_EXIT__;	
	}
	
    printBuffer("before decrypt:", aes_128_dst_buf, sizeof(aes_128_dst_buf));
    
    /* 7, use otp key loaded to cipher to decrypt data-->aes_128_dst_buf */ 
    s32Ret = HI_UNF_CIPHER_Decrypt(hTestchnid, u32InputAddrPhy, u32OutPutAddrPhy, u32TestDataLen);
    if(HI_SUCCESS != s32Ret)
	{
		HI_ERR_CIPHER("Cipher decrypt failed.\n");
		s32Ret = HI_FAILURE;
		goto __CIPHER_EXIT__;
	}

    printBuffer("decrypted text:", pOutputAddrVir, u32TestDataLen);
	/* compare */
    if ( 0 != memcmp(pOutputAddrVir, aes_128_src_buf, u32TestDataLen) )
    {
        HI_ERR_CIPHER("Memcmp failed!\n");
        s32Ret = HI_FAILURE;
        goto __CIPHER_EXIT__;
    }
    else
    {
        printf("Decrypt : verify ok!\n");
    }

__CIPHER_EXIT__:

    if (u32InputAddrPhy> 0)
    {
        HI_MMZ_Unmap(u32InputAddrPhy);
        HI_MMZ_Delete(u32InputAddrPhy);
    }
    if (u32OutPutAddrPhy > 0)
    {
        HI_MMZ_Unmap(u32OutPutAddrPhy);
        HI_MMZ_Delete(u32OutPutAddrPhy);
    }
    
    HI_UNF_CIPHER_DestroyHandle(hTestchnid);
    HI_UNF_CIPHER_DeInit();

    return s32Ret;
}


