//
//  NSData+PPAES.h
//  AppExtensionTester
//
//  Created by Pascal Pfiffner on 8/22/15.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface NSData (PPAES)

/**
 *  AES-256 encrypt the receiver with the given key.
 *
 *  @param key: String of 32 bytes length (will be null-padded otherwise)
 *  @return A new NSData instance representing the encrypted receiver
 */
- (NSData * __nullable)AES256EncryptWithKey:(NSString *)key;

/**
 *  Decrypt an AES-256 encrypted receiver.
 *
 *  @param key: String of 32 bytes length (will be null-padded otherwise)
 *  @return A new NSData instance representing the decrypted receiver
 */
- (NSData * __nullable)AES256DecryptWithKey:(NSString *)key;

@end

NS_ASSUME_NONNULL_END
