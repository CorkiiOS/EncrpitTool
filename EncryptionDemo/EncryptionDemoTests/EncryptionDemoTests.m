//
//  EncryptionDemoTests.m
//  EncryptionDemoTests
//
//  Created by 万启鹏 on 2018/6/26.
//  Copyright © 2018年 iCorki All rights reserved.
//

#import <XCTest/XCTest.h>
#import "NSString+DES_AES.h"
@interface EncryptionDemoTests : XCTestCase

@end

@implementation EncryptionDemoTests

- (void)setUp {
    [super setUp];
    // Put setup code here. This method is called before the invocation of each test method in the class.
}

- (void)tearDown {
    // Put teardown code here. This method is called after the invocation of each test method in the class.
    [super tearDown];
}

- (void)testExample {
    // This is an example of a functional test case.
    // Use XCTAssert and related functions to verify your tests produce the correct results.
}

- (void)testPerformanceExample {
    // This is an example of a performance test case.
    [self measureBlock:^{
        // Put the code you want to measure the time of here.
    }];
}

- (void)testDESEncript {
    NSString *content = @"1228888";
    NSString *key = @"jklslsl";
    NSString *encript = [content encryptStringWithKey:key iv:nil];
    XCTAssertTrue(encript.length > 0 , @"加密wancheng");
}

- (void)testDESDecript {
    NSString *content = @"1228888";
    NSString *key = @"jklslsl";
    NSString *encript = [content encryptStringWithKey:key iv:nil];
    XCTAssertTrue([[encript decryptStringWithKey:key iv:nil] isEqualToString:@"1228888"]);
}


@end
