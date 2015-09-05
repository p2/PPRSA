//
//  NSData+PPAES.m
//  AppExtensionTester
//
//  Created by Pascal Pfiffner on 8/22/15.
//

#import "NSData+PPAES.h"
#import <CommonCrypto/CommonCryptor.h>


@implementation NSData (PPAES)


- (NSData * __nullable)AES256EncryptWithKey:(NSString *)key {
	NSParameterAssert(key.length > 0);
	
	// block ciphers: output size is less than/equal to input size, plus one block size. So add one block size.
	size_t bufferSize = self.length + kCCBlockSizeAES128;
	void *buffer = malloc(bufferSize);
	
	// encrypt
	size_t encryptedLength = 0;
	CCCryptorStatus cryptStatus = CCCrypt(kCCEncrypt, kCCAlgorithmAES, kCCOptionPKCS7Padding,
										  (const void *)[key UTF8String], kCCKeySizeAES256,
										  NULL,
										  self.bytes, self.length,
										  buffer, bufferSize,
										  &encryptedLength);
	if (kCCSuccess == cryptStatus) {
		return [NSData dataWithBytesNoCopy:buffer length:encryptedLength];		// NSData takes care of the buffer
	}
	
	free(buffer);
	return nil;
}

- (NSData * __nullable)AES256DecryptWithKey:(NSString *)key {
	NSParameterAssert(key.length > 0);
	
	// block ciphers: output size is less than/equal to input size, plus one block size. So add one block size.
	size_t bufferSize = self.length + kCCBlockSizeAES128;
	void *buffer = malloc(bufferSize);
	
	// decrypt
	size_t decryptedLength = 0;
	CCCryptorStatus cryptStatus = CCCrypt(kCCDecrypt, kCCAlgorithmAES128, kCCOptionPKCS7Padding,
										  (const void *)[key UTF8String], kCCKeySizeAES256,
										  NULL,
										  self.bytes, self.length,
										  buffer, bufferSize,
										  &decryptedLength);
	
	if (cryptStatus == kCCSuccess) {
		return [NSData dataWithBytesNoCopy:buffer length:decryptedLength];		// NSData takes care of the buffer
	}
	
	free(buffer);
	return nil;
}


@end
