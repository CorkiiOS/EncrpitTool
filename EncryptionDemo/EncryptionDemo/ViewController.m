//
//  ViewController.m
//  002--RSA代码
//
//  Created by CC老师 on 2017/9/14.
//  Copyright © 2017年 Miss CC. All rights reserved.
//

#import "ViewController.h"
#import "RSACryptor.h"
#import "EncryptionTools.h"
@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view, typically from a nib.
    
    //1.获取公钥
    NSString *filePath = [[NSBundle mainBundle]pathForResource:@"rsacert.der" ofType:nil];
    
    [[RSACryptor sharedRSACryptor]loadPublicKey:filePath];
    
    //2.加载私钥 ，P12文件
    NSString *p12FilePath = [[NSBundle mainBundle]pathForResource:@"p.p12" ofType:nil];
    
    //password:生成p12文件时设置的密码
    [[RSACryptor sharedRSACryptor]loadPrivateKey:p12FilePath password:@"123456"];
    
    
}


- (void)touchesBegan:(NSSet<UITouch *> *)touches withEvent:(UIEvent *)event {
    
    
    NSData *result = [[RSACryptor sharedRSACryptor]encryptData:[@"hello" dataUsingEncoding:NSUTF8StringEncoding]];
    
    
    //base64
    NSString *base64 = [result base64EncodedDataWithOptions:0];
    
    NSLog(@"%@",base64);
    
    
    
    //解密
    NSData *D_data = [[RSACryptor sharedRSACryptor]decryptData:result];
    
    NSString *DString = [[NSString  alloc]initWithData:D_data encoding:NSUTF8StringEncoding];
    
    NSLog(@"解密的信息%@",DString);
    
    
    /*
     RSA + AES 组合（非对称 + 对称组合）
     1.利用AES对称 对数据本身加密
     2.RSA非对称算法，对AES的KEY加密
     
     
     
     */
    
}

- (void)des {
    // Do any additional setup after loading the view, typically from a nib.
    
    //AES - ECB 加密
    NSString *key = @"IC";
    
    //iv 向量
    //加密
    NSString *reslut =  [[EncryptionTools sharedEncryptionTools]encryptString:@"hello" keyString:key iv:nil];
    NSLog(@"加密结果：%@",reslut);
    
    //解密
    NSString *decryptString = [[EncryptionTools sharedEncryptionTools]decryptString:@"Y/sCmKUMJsN9NUUahvxCqA==" keyString:key iv:nil];
    NSLog(@"解密结果：%@",decryptString);
    
    
    
    //AES - CBC
    uint8_t iv[8] = {1,2,3,4,5,6,7,8};
    NSData *ivData = [NSData dataWithBytes:iv length:sizeof(iv)];
    
    NSString *CBC_EncryptString = [[EncryptionTools sharedEncryptionTools]encryptString:@"CCSmile" keyString:key iv:ivData];
    
    NSLog(@"CBC加密字符串 %@",CBC_EncryptString);
    
    
    NSString *CBC_DecryptString = [[EncryptionTools sharedEncryptionTools]decryptString:@"QoLihjsqqyc8jEozMvJdcQ==" keyString:key iv:ivData];
    
    
    NSLog(@"CBC解密字符串 %@",CBC_DecryptString);
    
    
    //DES - ECB
    [EncryptionTools sharedEncryptionTools].algorithm = kCCAlgorithmDES;
    NSString *DES_ECB_EncryptString =  [[EncryptionTools sharedEncryptionTools]encryptString:@"hello" keyString:key iv:nil];
    
    NSLog(@"DES_ECB加密字符串 %@",DES_ECB_EncryptString);
    
    NSString *ECB_CBC_DecryptString = [[EncryptionTools sharedEncryptionTools]decryptString:@"DHq5763/Eq4=" keyString:key iv:nil];
    NSLog(@"DES_ECB解密字符串 %@",ECB_CBC_DecryptString);
}

@end

