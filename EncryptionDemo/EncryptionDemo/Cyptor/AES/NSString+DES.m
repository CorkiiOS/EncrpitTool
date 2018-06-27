//
//  NSString+DES.m
//  EncryptionDemo
//
//  Created by 万启鹏 on 2018/6/26.
//  Copyright © 2018年 iCorki. All rights reserved.
//

#import "NSString+DES.h"
#import <CommonCrypto/CommonCryptor.h>
@implementation NSString (DES)

- (NSString *)DESEncryptStringWithKey:(NSString *)keyString iv:(NSData *)iv {
    
    if (self.length == 0 || keyString.length == 0) {
        return nil;
    }
    // 设置秘钥
    NSData *keyData = [keyString dataUsingEncoding:NSUTF8StringEncoding];
    uint8_t cKey[kCCKeySizeDES];
    bzero(cKey, sizeof(cKey));
    [keyData getBytes:cKey length:kCCKeySizeDES];
    
    // 设置iv
    uint8_t cIv[kCCBlockSizeDES];
    bzero(cIv, kCCBlockSizeDES);
    int option = 0;
    if (iv) {
        [iv getBytes:cIv length:kCCBlockSizeDES];
        option = kCCOptionPKCS7Padding;
    } else {
        option = kCCOptionPKCS7Padding | kCCOptionECBMode;
    }
    // 设置输出缓冲区
    NSData *data = [self dataUsingEncoding:NSUTF8StringEncoding];
    size_t bufferSize = [data length] + kCCBlockSizeDES;
    void *buffer = malloc(bufferSize);
    
    // 开始加密
    size_t encryptedSize = 0;
    /*
     CCCrypt:对称加密的核心函数（加密、解密）
     参数:
     1:加密kCCEncrypt、解密kCCDecrypt
     2:加密算法 AES/DES
     kCCAlgorithmAES     高级加密标准
     kCCAlgorithmDES     数据加密标准
     
     3.加密选项：ECB/CBC
     4.加密的密钥
     5.密钥长度
     6.iv 初始化向量
     7.加密的长度
     8.加密的数据长度
     9.密文的内存地址
     10.密文缓冲区大小
     11.加密结果大小
     */
    CCCryptorStatus cryptStatus = CCCrypt(kCCEncrypt,
                                          kCCAlgorithmDES,
                                          option,
                                          cKey,
                                          kCCKeySizeDES,
                                          cIv,
                                          [data bytes],
                                          [data length],
                                          buffer,
                                          bufferSize,
                                          &encryptedSize);
    
    NSData *result = nil;
    if (cryptStatus == kCCSuccess) {
        result = [NSData dataWithBytesNoCopy:buffer length:encryptedSize];
    } else {
        free(buffer);
        NSLog(@"[错误] 加密失败|状态编码: %d", cryptStatus);
    }
    
    return [result base64EncodedStringWithOptions:0];
}


- (NSString *)DESDecryptStringWithKey:(NSString *)keyString iv:(NSData *)iv {
    // 设置秘钥
    NSData *keyData = [keyString dataUsingEncoding:NSUTF8StringEncoding];
    uint8_t cKey[kCCKeySizeDES];
    bzero(cKey, sizeof(cKey));
    [keyData getBytes:cKey length:kCCKeySizeDES];
    
    // 设置iv
    uint8_t cIv[kCCBlockSizeDES];
    bzero(cIv, kCCBlockSizeDES);
    int option = 0;
    if (iv) {
        [iv getBytes:cIv length:kCCBlockSizeDES];
        option = kCCOptionPKCS7Padding;
    } else {
        option = kCCOptionPKCS7Padding | kCCOptionECBMode;
    }
    
    // 设置输出缓冲区
    NSData *data = [[NSData alloc] initWithBase64EncodedString:self options:0];
    size_t bufferSize = [data length] + kCCBlockSizeDES;
    void *buffer = malloc(bufferSize);
    
    // 开始解密
    size_t decryptedSize = 0;
    CCCryptorStatus cryptStatus = CCCrypt(kCCDecrypt,
                                          kCCAlgorithmDES,
                                          option,
                                          cKey,
                                          kCCKeySizeDES,
                                          cIv,
                                          [data bytes],
                                          [data length],
                                          buffer,
                                          bufferSize,
                                          &decryptedSize);
    
    NSData *result = nil;
    if (cryptStatus == kCCSuccess) {
        result = [NSData dataWithBytesNoCopy:buffer length:decryptedSize];
    } else {
        free(buffer);
        NSLog(@"[错误] 解密失败|状态编码: %d", cryptStatus);
    }
    
    return [[NSString alloc] initWithData:result encoding:NSUTF8StringEncoding];
}

@end
