//
//  NSString+DES_AES.h
//  EncryptionDemo
//
//  Created by 万启鹏 on 2018/6/26.
//  Copyright © 2018年 iCorki All rights reserved.
//

#import <Foundation/Foundation.h>

@interface NSString (DES_AES)

/*
 CBC 需要设置iv
 ECB iv 为 nil
 */

/**
 DES加密

 @param key 秘钥
 @param iv 偏移量
 @return 密文
 */
- (NSString *)encryptStringWithKey:(NSString *)key iv:(NSData *)iv;


/**
 DES解密

 @param key 秘钥
 @param iv 偏移量
 @return 明文
 */
- (NSString *)decryptStringWithKey:(NSString *)key iv:(NSData *)iv;





@end
